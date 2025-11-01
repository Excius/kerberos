import os
import sqlite3
import datetime
from flask import Flask, request, jsonify, send_file
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
import requests


from config.config import CA_COMMON_NAME, CA_ORGANIZATION, CA_PASSWORD, CA_PORT, PROVISIONING_SERVER_URL, REALM

# --- Configuration ---
CA_DATA_DIR = "/app/data"
DB_PATH = os.path.join(CA_DATA_DIR, "ca.db")
CA_KEY_PATH = os.path.join(CA_DATA_DIR, "ca_key.pem")
CA_CERT_PATH = os.path.join(CA_DATA_DIR, "ca_cert.pem")
ISSUED_CERTS_DIR = os.path.join(CA_DATA_DIR, "issued_certs")

INTERNAL_API_KEY = os.environ.get("INTERNAL_API_KEY")
if not INTERNAL_API_KEY:
    print("CRITICAL: INTERNAL_API_KEY environment variable not set.")
    # In a real app, you'd sys.exit(1) here
    # For now, we'll just print a warning

# Ensure directories exist
os.makedirs(CA_DATA_DIR, exist_ok=True)
os.makedirs(ISSUED_CERTS_DIR, exist_ok=True)

app = Flask(__name__)

# --- Database Functions ---
def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    with get_db() as conn:
        conn.execute("""
        CREATE TABLE IF NOT EXISTS certificates (
            serial_number INTEGER PRIMARY KEY,
            subject_name TEXT NOT NULL UNIQUE,
            principal_name TEXT NOT NULL UNIQUE,
            status TEXT NOT NULL,
            issued_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            expires_at TIMESTAMP NOT NULL
        );
        """)
        conn.commit()
    print("Database initialized.")

def get_next_serial():
    with get_db() as conn:
        cursor = conn.execute("SELECT MAX(serial_number) FROM certificates")
        max_serial = cursor.fetchone()[0]
    return (max_serial or 0) + 1

# --- CA Initialization ---
def load_or_create_ca():
    if os.path.exists(CA_KEY_PATH) and os.path.exists(CA_CERT_PATH):
        with open(CA_KEY_PATH, "rb") as f:
            ca_key = serialization.load_pem_private_key(f.read(), password=CA_PASSWORD)
        with open(CA_CERT_PATH, "rb") as f:
            ca_cert = x509.load_pem_x509_certificate(f.read())
        return ca_key, ca_cert
    
    print("Generating new CA key and certificate...")
    ca_key = rsa.generate_private_key(public_exponent=65537, key_size=4096)
    
    with open(CA_KEY_PATH, "wb") as f:
        f.write(ca_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.BestAvailableEncryption(CA_PASSWORD),
        ))

    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, "IN"),
        x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "Andhra Pradesh"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, CA_ORGANIZATION),
        x509.NameAttribute(NameOID.COMMON_NAME, CA_COMMON_NAME),
    ])
    
    ca_cert = x509.CertificateBuilder().subject_name(
        subject
    ).issuer_name(
        issuer
    ).public_key(
        ca_key.public_key()
    ).serial_number(
        x509.random_serial_number()
    ).not_valid_before(
        datetime.datetime.now(datetime.timezone.utc)
    ).not_valid_after(
        datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=1825)
    ).add_extension(
        x509.BasicConstraints(ca=True, path_length=None), critical=True,
    ).sign(ca_key, hashes.SHA256())

    with open(CA_CERT_PATH, "wb") as f:
        f.write(ca_cert.public_bytes(serialization.Encoding.PEM))
        
    print("New CA key and certificate generated.")
    return ca_key, ca_cert

# --- API Endpoints ---
@app.route('/ca-cert', methods=['GET'])
def get_ca_cert():
    """Provides the CA's public certificate so clients can trust it."""
    return send_file(CA_CERT_PATH, mimetype='application/x-pem-file')

@app.route('/submit-csr', methods=['POST'])
def submit_csr():
    """Receives a CSR, signs it, and calls the provisioning server."""
    csr_pem = request.data
    if not csr_pem:
        return jsonify({"error": "No CSR provided"}), 400
    
    if not INTERNAL_API_KEY:
        return jsonify({"error": "CA server is not configured with an internal API key."}), 500

    try:
        csr = x509.load_pem_x509_csr(csr_pem)
        
        ca_key, ca_cert = load_or_create_ca() # Load CA
        serial = get_next_serial()
        common_name = csr.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value
        subject_name_str = csr.subject.rfc4514_string()
        not_valid_after = datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=365)

        with get_db() as conn:
            cursor = conn.execute(
                "SELECT * FROM certificates WHERE principal_name = ?",
                (f"{common_name}@{REALM}",)
            )
            user = cursor.fetchone()
            if user:
                return jsonify({"error": f"User '{common_name}' already found in database."}), 404

        subject = x509.Name([
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "MyKerberosCA"),
            x509.NameAttribute(NameOID.COMMON_NAME, f"{common_name}@"+REALM),
        ])
        
        new_cert = x509.CertificateBuilder().subject_name(
            subject
        ).issuer_name(
            ca_cert.subject
        ).public_key(
            csr.public_key()
        ).serial_number(
            serial
        ).not_valid_before(
            datetime.datetime.now(datetime.timezone.utc)
        ).not_valid_after(
            not_valid_after
        ).add_extension(
            x509.BasicConstraints(ca=False, path_length=None), critical=True,
        ).sign(ca_key, hashes.SHA256())

        new_cert_pem = new_cert.public_bytes(serialization.Encoding.PEM)

        fingerprint = new_cert.fingerprint(hashes.SHA256()).hex()

        # Log it to the database (but don't commit yet)
        conn = get_db()
        conn.execute(
            "INSERT INTO certificates (serial_number, subject_name, principal_name, status, expires_at) VALUES (?, ?, ?, ?, ?)",
            (serial, subject_name_str, f"{common_name}@"+REALM,"issued", not_valid_after)
        )

        # Save the new certificate
        cert_filename = f"{common_name.replace(' ', '_')}_{serial}.pem"
        cert_path = os.path.join(ISSUED_CERTS_DIR, cert_filename)
        with open(cert_path, "wb") as f:
            f.write(new_cert_pem)

        

        print(f"Issued certificate for {common_name}")

        # --- Call Provisioning Server ---
        res = None
        provisioning_success = False
        try:
            print(f"Calling provisioning server for user: {common_name}")
            provision_payload = {
                "username": common_name,
                "cert_subject": subject_name_str,
                "cert_fingerprint": fingerprint
            }
            PROVISIONING_SERVER_ROUTE = PROVISIONING_SERVER_URL+"/create-user"

            # --- NEW: Add the Authorization Header ---
            headers = {
                "Authorization": f"Bearer {INTERNAL_API_KEY}",
                "Content-Type": "application/json"
            }

            res = requests.post(PROVISIONING_SERVER_ROUTE, json=provision_payload, headers=headers, timeout=5)
            
            if res.status_code in (201, 409):  # 201=Created, 409=Conflict (already exists)
                provisioning_success = True
                print(f"Provisioning server call successful (Status: {res.status_code})")
            else:
                print(f"WARNING: Failed to provision user '{common_name}'.")
                print(f"Provisioning server responded with {res.status_code}: {res.text}")

        except requests.exceptions.RequestException as e:
            # Handle cases where the provisioning server is down
            print(f"CRITICAL: Could not connect to provisioning server at {PROVISIONING_SERVER_ROUTE}")
            print(f"Error: {e}")

        if provisioning_success:
            # Commit the database changes
            conn.commit()
            
            # Save the new certificate
            cert_filename = f"{common_name.replace(' ', '_')}_{serial}.pem"
            cert_path = os.path.join(ISSUED_CERTS_DIR, cert_filename)
            with open(cert_path, "wb") as f:
                f.write(new_cert_pem)

            print(f"Issued certificate for {common_name}")

            # Get principal_name from provisioning response
            principal_name = None
            if res and res.status_code == 201:
                try:
                    principal_name = res.json().get('principal_name')
                except Exception as e:
                    print(f"Error parsing provisioning response: {e}")

            # Return the certificate and principal_name to the user
            conn.close()
            return jsonify({
                "status": "success",
                "certificate": new_cert_pem.decode('utf-8'),
                "principal_name": principal_name,
                "subject": subject_name_str,
                "fingerprint": fingerprint
            }), 201
        else:
            # Revert changes
            conn.rollback()
            conn.close()
            return jsonify({"error": "Failed to provision user in KDC. Certificate issuance reverted."}), 500

    except Exception as e:
        print(f"Error signing CSR: {e}")
        return jsonify({"error": f"Failed to sign CSR: {e}"}), 500

if __name__ == "__main__":
    print("--- Starting CA API Server ---")
    init_db()
    load_or_create_ca()
    app.run(host='0.0.0.0', port=CA_PORT)