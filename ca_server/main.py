import base64
from functools import wraps
import os
import datetime
import uuid
from flask import Flask, request, jsonify, send_file, g
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding as asym_padding
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicKey
from cryptography.exceptions import InvalidSignature
import requests


from ca_server.database import get_db, init_db
from config.config import (
    CA_COMMON_NAME,
    CA_ORGANIZATION,
    CA_PASSWORD,
    CA_PORT,
    PROVISIONING_SERVER_URL,
    REALM,
)

# --- Configuration ---
CA_DATA_DIR = "/app/data"
CA_KEY_PATH = os.path.join(CA_DATA_DIR, "ca_key.pem")
CA_CERT_PATH = os.path.join(CA_DATA_DIR, "ca_cert.pem")
ISSUED_CERTS_DIR = os.path.join(CA_DATA_DIR, "issued_certs")

INTERNAL_API_KEY = os.environ.get("INTERNAL_API_KEY")
if not INTERNAL_API_KEY:
    print("CRITICAL: INTERNAL_API_KEY environment variable not set.")
    # In a real app, you'd sys.exit(1) here

# Ensure directories exist
os.makedirs(ISSUED_CERTS_DIR, exist_ok=True)

app = Flask(__name__)


# --- CA Initialization ---
def load_or_create_ca():
    """Loads or creates the CA key and root certificate."""
    if os.path.exists(CA_KEY_PATH) and os.path.exists(CA_CERT_PATH):
        with open(CA_KEY_PATH, "rb") as f:
            ca_key = serialization.load_pem_private_key(f.read(), password=CA_PASSWORD)
        with open(CA_CERT_PATH, "rb") as f:
            ca_cert = x509.load_pem_x509_certificate(f.read())
        return ca_key, ca_cert

    print("Generating new CA key and certificate...")
    ca_key = rsa.generate_private_key(public_exponent=65537, key_size=4096)

    with open(CA_KEY_PATH, "wb") as f:
        f.write(
            ca_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.BestAvailableEncryption(CA_PASSWORD),
            )
        )

    subject = issuer = x509.Name(
        [
            x509.NameAttribute(NameOID.COUNTRY_NAME, "IN"),
            x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "Andhra Pradesh"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, CA_ORGANIZATION),
            x509.NameAttribute(NameOID.COMMON_NAME, CA_COMMON_NAME),
        ]
    )

    ca_cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(ca_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.datetime.now(datetime.timezone.utc))
        .not_valid_after(
            datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=1825)
        )
        .add_extension(
            x509.BasicConstraints(ca=True, path_length=None),
            critical=True,
        )
        .sign(ca_key, hashes.SHA256())
    )

    with open(CA_CERT_PATH, "wb") as f:
        f.write(ca_cert.public_bytes(serialization.Encoding.PEM))

    print("New CA key and certificate generated.")
    return ca_key, ca_cert


def get_next_serial():
    """Gets the next available serial number from the DB."""
    with get_db() as conn:
        cursor = conn.execute("SELECT MAX(serial_number) FROM certificates")
        max_serial = cursor.fetchone()[0]
    # Return next serial number, starting from 1 if DB is empty
    return (max_serial or 0) + 1


# --- Security Decorator ---
def require_trusted_device(f):
    """
    Decorator to authenticate a request using a client certificate.
    This proves the request is from an existing, trusted device.
    """

    @wraps(f)
    def decorated_function(*args, **kwargs):
        # 1. Get auth headers
        auth_cert_pem_b64 = request.headers.get("X-Client-Cert")
        auth_signature = request.headers.get("X-Client-Signature")
        auth_timestamp = request.headers.get("X-Client-Timestamp")

        if not all([auth_cert_pem_b64, auth_signature, auth_timestamp]):
            return jsonify({"error": "Missing client authentication headers"}), 401

        try:
            # 2. Verify the certificate itself
            auth_cert_pem = base64.b64decode(auth_cert_pem_b64).decode("utf-8")
            auth_cert = x509.load_pem_x509_certificate(auth_cert_pem.encode("utf-8"))
            ca_key, ca_cert = load_or_create_ca()

            ca_public_key = ca_cert.public_key()
            if not isinstance(ca_public_key, rsa.RSAPublicKey):
                return jsonify({"error": "CA public key must be RSA"}), 500

            if auth_cert.signature_hash_algorithm is None:
                return jsonify(
                    {"error": "Certificate signature algorithm is unknown"}
                ), 400

            try:
                ca_public_key.verify(
                    signature=auth_cert.signature,
                    data=auth_cert.tbs_certificate_bytes,
                    padding=asym_padding.PKCS1v15(),
                    algorithm=auth_cert.signature_hash_algorithm,
                )
            except InvalidSignature:
                return jsonify(
                    {"error": "Certificate signature is invalid (not CA-signed)."}
                ), 401

            if auth_cert.issuer != ca_cert.subject:
                return jsonify({"error": "Certificate issuer is not this CA"}), 401

            # 3. Check if this cert is trusted in our DB
            auth_fingerprint = auth_cert.fingerprint(hashes.SHA256()).hex()
            with get_db() as conn:
                cursor = conn.execute(
                    "SELECT * FROM certificates WHERE fingerprint = ? AND status = 'trusted'",
                    (auth_fingerprint,),
                )
                trusted_cert_row = cursor.fetchone()

            if not trusted_cert_row:
                return jsonify(
                    {"error": "Certificate is not trusted or not found"}
                ), 403

            # 4. Verify the signature (proves possession of private key)
            public_key = auth_cert.public_key()
            if not isinstance(public_key, RSAPublicKey):
                return jsonify({"error": "Auth certificate must be RSA"}), 400

            if auth_signature is None:
                return jsonify({"error": "Missing client signature"}), 401

            public_key.verify(
                base64.b64decode(auth_signature),
                auth_timestamp.encode("utf-8"),  # We just sign the timestamp
                asym_padding.PKCS1v15(),
                hashes.SHA256(),
            )

            # 5. Check timestamp freshness
            ts = datetime.datetime.fromisoformat(auth_timestamp.replace("Z", "+00:00"))
            if (
                abs((datetime.datetime.now(datetime.timezone.utc) - ts).total_seconds())
                > 300
            ):  # 5 min window
                return jsonify(
                    {"error": "Auth timestamp is stale (replay attack)"}
                ), 401

            # If all checks pass, attach the trusted principal to the request (store on flask.g)
            g.principal_name = trusted_cert_row["principal_name"]

        except InvalidSignature:
            return jsonify({"error": "Invalid client signature"}), 401
        except Exception as e:
            return jsonify({"error": f"Client authentication failed: {e}"}), 500

        return f(*args, **kwargs)

    return decorated_function


# --- API Endpoints ---
@app.route("/ca-cert", methods=["GET"])
def get_ca_cert():
    """Provides the CA's public certificate so clients can trust it."""
    try:
        return send_file(CA_CERT_PATH, mimetype="application/x-pem-file")
    except FileNotFoundError:
        return jsonify(
            {"error": "CA certificate not found. Has the CA been initialized?"}
        ), 404


@app.route("/submit-csr", methods=["POST"])
def submit_csr():
    """
    Endpoint for clients to submit a CSR (Certificate Signing Request).
    Handles both new user signups and new device registrations.
    """
    try:
        data = request.get_json(silent=True) or {}
        csr_pem = data.get("csr_pem")
        is_signup = data.get("is_signup", False)

        if not csr_pem:
            return jsonify({"error": "CSR PEM is required"}), 400

        # Parse CSR
        csr = x509.load_pem_x509_csr(csr_pem.encode("utf-8"))
        common_name = csr.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value
        subject_name_str = csr.subject.rfc4514_string()
        new_principal_name = f"{common_name}@{REALM}"

        with get_db() as conn:
            # Check if this user already exists
            cursor = conn.execute(
                "SELECT * FROM certificates WHERE principal_name = ?",
                (new_principal_name,),
            )
            existing_user = cursor.fetchone()

        # -----------------------
        # 1️⃣ SIGNUP FLOW (NEW USER)
        # -----------------------
        if is_signup:
            if existing_user:
                return jsonify({"error": "User already exists"}), 409

            print(f"New user detected: {new_principal_name}")
            new_cert_pem, fingerprint = _sign_and_save_cert(
                csr, new_principal_name, False
            )

            if not _provision_new_user(common_name, subject_name_str, fingerprint):
                _revert_cert_issuance(fingerprint)
                return jsonify({"error": "Failed to provision user in KDC"}), 500

            return jsonify(
                {
                    "status": "approved",
                    "certificate": new_cert_pem.decode("utf-8"),
                }
            ), 201

        # -----------------------
        # 2️⃣ LOGIN / NEW DEVICE FLOW
        # -----------------------
        else:
            if not existing_user:
                return jsonify({"error": "No such user exists"}), 409

            print(f"New device request for existing user: {new_principal_name}")

            # Issue new cert for this device
            new_cert_pem, fingerprint = _sign_and_save_cert(
                csr, new_principal_name, True
            )
            request_id = str(uuid.uuid4())

            with get_db() as conn:
                conn.execute(
                    """
                    INSERT INTO pending_requests
                        (request_id, principal_name, new_csr_pem, new_cert_subject, fingerprint, status)
                    VALUES (?, ?, ?, ?, ?, 'pending')
                    """,
                    (
                        request_id,
                        new_principal_name,
                        csr_pem,
                        subject_name_str,
                        fingerprint,
                    ),
                )

            return jsonify(
                {
                    "status": "pending_approval",
                    "request_id": request_id,
                    "message": "Request received. Please approve from a trusted device.",
                }
            ), 202

    except Exception as e:
        print(f"Error processing CSR: {e}")
        return jsonify({"error": f"Failed to process CSR: {e}"}), 500


@app.route("/poll-pending-requests", methods=["POST"])
@require_trusted_device
def poll_pending_requests():
    """
    Authenticated endpoint for a trusted device to check for
    pending approval requests for its user.
    """
    principal_name = g.principal_name  # Injected by decorator

    with get_db() as conn:
        cursor = conn.execute(
            "SELECT request_id, new_cert_subject, created_at FROM pending_requests WHERE principal_name = ? AND status = 'pending'",
            (principal_name,),
        )
        requests = [dict(row) for row in cursor.fetchall()]

    return jsonify({"status": "ok", "pending_requests": requests}), 200


@app.route("/approve-request", methods=["POST"])
@require_trusted_device
def approve_request():
    """
    Authenticated endpoint for a trusted device to approve or reject a pending request.
    Expects JSON: { "request_id": "...", "action": "approve" | "reject" }
    """
    principal_name = g.principal_name  # Injected by @require_trusted_device
    data = request.get_json(silent=True) or {}
    request_id = data.get("request_id")
    action = data.get("action", "approve").lower()

    if not request_id:
        return jsonify({"error": "request_id is required"}), 400

    try:
        with get_db() as conn:
            # 1. Lookup pending request
            cursor = conn.execute(
                "SELECT * FROM pending_requests WHERE request_id = ? AND status = 'pending'",
                (request_id,),
            )
            request_row = cursor.fetchone()

            if not request_row:
                return jsonify({"error": "Request not found or already processed"}), 404

            # 2. Security check
            if request_row["principal_name"] != principal_name:
                return jsonify(
                    {
                        "error": "You are not authorized to approve or reject this request"
                    }
                ), 403

            # --- Handle Approval ---
            if action == "approve":
                print(f"Approving request {request_id} for {principal_name}")
                fingerprint = request_row["fingerprint"]
                subject_name_str = request_row["new_cert_subject"]

                # Provision the new device (e.g., register in KDC)
                if not _provision_new_device(
                    principal_name, subject_name_str, fingerprint
                ):
                    return jsonify(
                        {"error": "Failed to provision new device in KDC"}
                    ), 500

                conn.execute(
                    "UPDATE pending_requests SET status = 'approved' WHERE request_id = ?",
                    (request_id,),
                )
                conn.execute(
                    "UPDATE certificates SET status = 'trusted' WHERE fingerprint = ?",
                    (fingerprint,),
                )

                return jsonify(
                    {
                        "status": "approved",
                        "message": "New device approved and provisioned.",
                    }
                ), 200

            # --- Handle Rejection ---
            elif action == "reject":
                print(f"Rejecting request {request_id} for {principal_name}")
                conn.execute(
                    "UPDATE pending_requests SET status = 'rejected' WHERE request_id = ?",
                    (request_id,),
                )
                return jsonify(
                    {"status": "rejected", "message": "Request has been rejected."}
                ), 200

            else:
                return jsonify(
                    {
                        "error": f"Invalid action '{action}'. Must be 'approve' or 'reject'."
                    }
                ), 400

    except Exception as e:
        print(f"Error approving/rejecting request: {e}")
        return jsonify({"error": f"Failed to process request: {e}"}), 500


@app.route("/check-request-status/<request_id>", methods=["GET"])
def check_request_status(request_id):
    """
    Unauthenticated endpoint for the new (pending) device to poll
    to see if its request has been approved.
    """
    try:
        with get_db() as conn:
            cursor = conn.execute(
                "SELECT * FROM pending_requests WHERE request_id = ?", (request_id,)
            )
            request_row = cursor.fetchone()

            if not request_row:
                return jsonify({"error": "Request not found"}), 404

            fingerprint = request_row["fingerprint"]

            if request_row["status"] == "pending":
                return jsonify({"status": "pending_approval"}), 200

            if request_row["status"] == "rejected":
                return jsonify({"status": "rejected"}), 200

            if request_row["status"] == "approved":
                print(f"Request {request_id} approved, retrieving certificate.")
                # Get the newly signed cert and return it

                if not fingerprint:
                    return jsonify({"error": "Missing certificate fingerprint"}), 500

                cursor_cert = conn.execute(
                    "SELECT * FROM certificates WHERE fingerprint = ?", (fingerprint,)
                )
                cert_row = cursor_cert.fetchone()

                if not cert_row:
                    return jsonify(
                        {"error": "Approved, but certificate not found."}
                    ), 500

                # Find the cert on disk
                serial_number = cert_row["serial_number"]
                common_name = cert_row["principal_name"].split("@")[0]
                cert_filename = f"{common_name.replace(' ', '_')}_{serial_number}.pem"
                cert_path = os.path.join(ISSUED_CERTS_DIR, cert_filename)

                if not os.path.exists(cert_path):
                    return jsonify(
                        {"error": "Certificate file not found on disk."}
                    ), 500

                with open(cert_path, "rb") as f:
                    cert_pem = f.read().decode("utf-8")

                return jsonify({"status": "approved", "certificate": cert_pem}), 200

            return jsonify({"status": request_row["status"]}), 200  # Should not happen

    except Exception as e:
        print(f"Error checking status: {e}")
        return jsonify({"error": f"Error checking status: {e}"}), 500


# --- Internal Helper Functions ---


def _sign_and_save_cert(csr, principal_name, pending):
    """Signs a CSR, saves it, and logs it to the DB. Returns (pem, fingerprint)."""
    ca_key, ca_cert = load_or_create_ca()
    serial = get_next_serial()
    not_valid_after = datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(
        days=365
    )

    common_name = csr.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value

    subject = x509.Name(
        [
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, CA_ORGANIZATION),
            x509.NameAttribute(NameOID.COMMON_NAME, f"{common_name}"),
        ]
    )

    new_cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(ca_cert.subject)
        .public_key(csr.public_key())
        .serial_number(serial)
        .not_valid_before(datetime.datetime.now(datetime.timezone.utc))
        .not_valid_after(not_valid_after)
        .add_extension(
            x509.BasicConstraints(ca=False, path_length=None),
            critical=True,
        )
        .sign(ca_key, hashes.SHA256())
    )

    new_cert_pem = new_cert.public_bytes(serialization.Encoding.PEM)
    fingerprint = new_cert.fingerprint(hashes.SHA256()).hex()
    subject_name_str = subject.rfc4514_string()

    if pending:
        status = "pending"
    else:
        status = "trusted"

    with get_db() as conn:
        conn.execute(
            "INSERT INTO certificates (serial_number, subject_name, principal_name, status, expires_at, fingerprint) VALUES (?, ?, ?, ?, ?, ?)",
            (
                serial,
                subject_name_str,
                principal_name,
                status,
                not_valid_after,
                fingerprint,
            ),
        )

    cert_filename = f"{common_name.replace(' ', '_')}_{serial}.pem"
    cert_path = os.path.join(ISSUED_CERTS_DIR, cert_filename)
    with open(cert_path, "wb") as f:
        f.write(new_cert_pem)

    return new_cert_pem, fingerprint


def _revert_cert_issuance(fingerprint):
    """Removes a certificate from the DB if provisioning fails."""
    try:
        with get_db() as conn:
            conn.execute(
                "DELETE FROM certificates WHERE fingerprint = ?", (fingerprint,)
            )
        print(f"Reverted certificate issuance for fingerprint: {fingerprint}")
    except Exception as e:
        print(f"CRITICAL: Failed to revert DB entry: {e}")


def _call_provisioning_server(endpoint, payload):
    """Helper to call the provisioning server with the API key."""
    if not INTERNAL_API_KEY:
        print("CRITICAL: INTERNAL_API_KEY is not set. Cannot call provisioning server.")
        return False

    try:
        url = f"{PROVISIONING_SERVER_URL}/{endpoint}"
        headers = {
            "Authorization": f"Bearer {INTERNAL_API_KEY}",
            "Content-Type": "application/json",
        }
        res = requests.post(url, json=payload, headers=headers, timeout=5)

        if res.status_code in (201, 409):  # Created or Conflict (already exists)
            print(
                f"Provisioning server call to {endpoint} successful (Status: {res.status_code})"
            )
            return True
        else:
            print(f"WARNING: Provisioning server call to {endpoint} failed.")
            print(f"Responded with {res.status_code}: {res.text}")
            return False

    except requests.exceptions.RequestException as e:
        print(
            f"CRITICAL: Could not connect to provisioning server at {PROVISIONING_SERVER_URL}"
        )
        print(f"Error: {e}")
        return False


def _provision_new_user(username, cert_subject, cert_fingerprint):
    """Calls the provisioning server to create a new user AND their first device."""
    payload = {
        "username": username,
        "cert_subject": cert_subject,
        "cert_fingerprint": cert_fingerprint,
    }
    return _call_provisioning_server("provision-new-user", payload)


def _provision_new_device(principal_name, cert_subject, cert_fingerprint):
    """Calls the provisioning server to add a new device to an existing user."""
    payload = {
        "principal_name": principal_name,
        "cert_subject": cert_subject,
        "cert_fingerprint": cert_fingerprint,
    }
    return _call_provisioning_server("add-device", payload)


# --- Main ---
if __name__ == "__main__":
    print("--- Starting CA API Server (Multi-Device) ---")
    init_db()
    load_or_create_ca()
    app.run(host="0.0.0.0", port=CA_PORT, debug=True)
