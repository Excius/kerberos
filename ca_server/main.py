import os
import sqlite3
import datetime
from flask import Flask, request, jsonify, send_file
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
import requests


from config.config import CA_PASSWORD, PROVISIONING_SERVER_URL

# --- Configuration ---
DATA_DIR = "/app/data"
DB_PATH = os.path.join(DATA_DIR, "ca.db")
CA_KEY_PATH = os.path.join(DATA_DIR, "ca_key.pem")
CA_CERT_PATH = os.path.join(DATA_DIR, "ca_cert.pem")
ISSUED_CERTS_DIR = os.path.join(DATA_DIR, "issued_certs")

# Ensure directories exist
os.makedirs(DATA_DIR, exist_ok=True)
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
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "MyKerberosProject"),
        x509.NameAttribute(NameOID.COMMON_NAME, "MyKerberosProject CA"),
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

    try:
        csr = x509.load_pem_x509_csr(csr_pem)
        
        ca_key, ca_cert = load_or_create_ca() # Load CA
        
        serial = get_next_serial()
        common_name = csr.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value
        subject_name_str = csr.subject.rfc4514_string()
        not_valid_after = datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=365)
        
        new_cert = x509.CertificateBuilder().subject_name(
            csr.subject
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

        # Save the new certificate
        cert_filename = f"{common_name.replace(' ', '_')}_{serial}.pem"
        cert_path = os.path.join(ISSUED_CERTS_DIR, cert_filename)
        with open(cert_path, "wb") as f:
            f.write(new_cert_pem)

        # Log it to the database
        with get_db() as conn:
            conn.execute(
                "INSERT INTO certificates (serial_number, subject_name, status, expires_at) VALUES (?, ?, ?, ?)",
                (serial, subject_name_str, "issued", not_valid_after)
            )
            conn.commit()

        print(f"Issued certificate for {common_name}")

        # --- NEW: Call Provisioning Server ---
        try:
            print(f"Calling provisioning server for user: {common_name}")
            provision_payload = {
                "username": common_name,
                "cert_subject": subject_name_str
            }
            PROVISIONING_SERVER_ROUTE = PROVISIONING_SERVER_URL+"/create-user"
            res = requests.post(PROVISIONING_SERVER_ROUTE, json=provision_payload, timeout=5)
            
            if res.status_code not in (201, 409): # 201=Created, 409=Conflict (already exists)
                # If provisioning failed for a reason other than "already exists",
                # we should log it. In a real system, you might "roll back" the
                # certificate issuance or mark it as "pending provisioning".
                print(f"WARNING: Failed to provision user '{common_name}'.")
                print(f"Provisioning server responded with {res.status_code}: {res.text}")
            else:
                print(f"Provisioning server call successful (Status: {res.status_code})")

        except requests.exceptions.RequestException as e:
            # Handle cases where the provisioning server is down
            print(f"CRITICAL: Could not connect to provisioning server at {PROVISIONING_SERVER_ROUTE}")
            print(f"Error: {e}")
            # This is a problem. The user has a cert but no KDC account.
            # In a real app, you'd add this to a retry queue.
        # --- END NEW SECTION ---

        # Return the certificate to the user
        return new_cert_pem, 201, {'Content-Type': 'application/x-pem-file'}

    except Exception as e:
        print(f"Error signing CSR: {e}")
        return jsonify({"error": f"Failed to sign CSR: {e}"}), 500

if __name__ == "__main__":
    print("--- Starting CA API Server ---")
    init_db()
    load_or_create_ca()
    app.run(host='0.0.0.0', port=5000)