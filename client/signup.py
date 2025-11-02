import requests
import os
import sys
import json
import time
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa

# --- Configuration ---
# Add parent directory to path to import config
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
try:
    from config.config import REALM, CA_PORT
except ImportError:
    print("Error: config/config.py not found. Please create it.")
    print("Using default values for testing.")
    REALM = "YOUR_REALM"
    CA_PORT = 5000

USER_NAME = "testuser"
PRINCIPAL_NAME = f"{USER_NAME}@{REALM}"

# Local paths for credentials (to be run from host)
CERT_DIR = os.path.join(os.getcwd(), "cert")
# Create it if it doesn't exist
os.makedirs(CERT_DIR, exist_ok=True)

USER_KEY_PATH = os.path.join(CERT_DIR, "client.key")
USER_CERT_PATH = os.path.join(CERT_DIR, "client.crt")

# URL for the CA server (running on localhost)
CA_URL = f"http://localhost:{CA_PORT}"

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

        # 2. Save the private key
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
    ).sign(key, hashes.SHA256()) 

    csr_pem = csr.public_bytes(serialization.Encoding.PEM)

    # 4. Submit the CSR to the CA Server API
    print(f"Submitting CSR to CA at {CA_URL}...")
    try:
        # This is the payload for the *new* /submit-csr endpoint
        payload = {
            "principal_name": PRINCIPAL_NAME,
            "csr_pem": csr_pem.decode('utf-8')
        }
        
        response = requests.post(
            f"{CA_URL}/submit-csr",
            json=payload, # Send as JSON
            timeout=10
        )

        data = response.json()

        if response.status_code == 201:
            # 5. Receive the signed certificate and save it (NEW USER)
            with open(USER_CERT_PATH, "wb") as f:
                f.write(data['certificate'].encode('utf-8'))
            
            print(f"Success! New user provisioned.")
            print(f"Received and saved certificate to: {USER_CERT_PATH}")

        elif response.status_code == 202:
            # 5b. Handle pending request (NEW DEVICE)
            request_id = data['request_id']
            print(f"This is a new device for an existing user.")
            print(f"Request ID: {request_id}")
            print("Please approve this request from a trusted device.")
            # We would now start polling /check-request-status
            # For this test, we'll just stop.
            
        elif response.status_code == 409:
             print(f"Error: {data.get('error')}")
             print("This user/device may already be registered. Trying to log in...")
        
        else:
            print(f"Error: {response.status_code}")
            print(response.text)

    except requests.exceptions.ConnectionError as e:
        print(f"\nConnection Error: Could not connect to CA server at {CA_URL}.")
        print("Please ensure all Docker services are running with 'docker-compose up'.")
    except Exception as e:
        print(f"\nAn unexpected error occurred: {e}")

if __name__ == "__main__":
    # Wait for the CA service to be ready
    import time
    print("Waiting 5s for CA server to be ready...")
    time.sleep(5)
    run_signup()

