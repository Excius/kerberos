import requests
import os
import json
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa

# --- Configuration ---
# This is the directory that client/main.py ALSO uses.
# It's the mounted 'ca-data' volume.
CERT_DIR = "/app/certs"
USER_NAME = "testuser"
USER_KEY_PATH = os.path.join(CERT_DIR, f"{USER_NAME}_key.pem")
USER_CERT_PATH = os.path.join(CERT_DIR, f"{USER_NAME}_cert.pem")

# URL for the CA server (using the internal Docker service name)
CA_URL = "http://localhost:5000"

def run_signup():
    """
    Generates a new user key IF ONE DOESN'T EXIST, then submits a 
    CSR to the CA to get a new certificate.
    """
    
    print(f"--- Running signup for user: {USER_NAME} ---")

    # Check if user key already exists
    if os.path.exists(USER_KEY_PATH):
        print(f"Existing key found. Loading key from: {USER_KEY_PATH}")
        try:
            with open(USER_KEY_PATH, "rb") as f:
                key = serialization.load_pem_private_key(
                    f.read(),
                    password=None # Assuming no password
                )
        except Exception as e:
            print(f"Error loading existing key: {e}. Aborting.")
            return
    else:
        # 1. Generate new private key
        print("No existing key found. Generating new private key...")
        key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
        )

        # 2. Save the private key (THEY KEEP THIS SECRET)
        # We save it directly to the shared volume path
        print(f"Saving new private key to: {USER_KEY_PATH}")
        with open(USER_KEY_PATH, "wb") as f:
            f.write(key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption(),
            ))
    
    # 3. Create a Certificate Signing Request (CSR)
    # We always do this step to get a new/refreshed certificate
    print("Creating CSR...")
    csr = x509.CertificateSigningRequestBuilder().subject_name(
        x509.Name([
            x509.NameAttribute(NameOID.COUNTRY_NAME, "IN"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "MyKerberosProject"),
            x509.NameAttribute(NameOID.COMMON_NAME, USER_NAME),
        ])
    ).sign(key, hashes.SHA256()) # Sign the CSR with our private key (FIXED typo)

    csr_pem = csr.public_bytes(serialization.Encoding.PEM)

    # 4. Submit the CSR to the CA Server API
    print(f"Submitting CSR to CA at {CA_URL}...")
    try:
        response = requests.post(
            f"{CA_URL}/submit-csr",
            data=csr_pem,
            headers={'Content-Type': 'application/pem-certificate-request'},
            timeout=10
        )

        if response.status_code == 201:
            # 5. Receive the signed certificate and save it
            # This will OVERWRITE any existing certificate
            data = response.json()
            with open(USER_CERT_PATH, "wb") as f:
                f.write(data['certificate'].encode('utf-8'))
            
            print(f"Success! Received and saved/overwritten certificate to: {USER_CERT_PATH}")
            print(f"User provisioned: {data.get('principal_name')}")
        else:
            print(f"Error: {response.status_code}")
            print(response.text)

    except requests.exceptions.ConnectionError as e:
        print(f"Connection Error: Could not connect to CA server at {CA_URL}.")
        print("Is the 'ca-server' running?")
    except Exception as e:
        print(f"An unexpected error occurred: {e}")

if __name__ == "__main__":
    # This script is intended to be run from INSIDE the client container
    # e.g., `docker-compose exec client python client/signup.py`
    # It will connect to the 'ca-server' service and save the
    # credentials to the shared /app/certs volume.
    
    # Let's add a small delay to ensure the CA is ready
    import time
    print("Waiting 5s for CA server to be ready...")
    time.sleep(5)
    run_signup()

