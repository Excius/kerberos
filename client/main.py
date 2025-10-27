import socket
import json
import base64
import os
import datetime
import time
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding

# --- Configuration ---
# These paths point to the certs in the shared 'ca-data' volume
# The client container's docker-compose.yml maps 'ca-data' to '/app/certs'
CERT_DIR = "/app/certs"
USER_CERT_PATH = os.path.join(CERT_DIR, "testuser_cert.pem")
USER_KEY_PATH = os.path.join(CERT_DIR, "testuser_key.pem")
CA_CERT_PATH = os.path.join(CERT_DIR, "ca_cert.pem")

KDC_HOST = "primary-kdc"
KDC_PORT = 8888
USER_PRINCIPAL = "testuser@YOUR_REALM" # The principal name

def load_credentials():
    """Loads the user's certificate and private key."""
    try:
        with open(USER_CERT_PATH, "rb") as f:
            cert_pem = f.read()
            cert = x509.load_pem_x509_certificate(cert_pem)
        
        with open(USER_KEY_PATH, "rb") as f:
            key_pem = f.read()
            # We assume no password on the client key for this project
            key = serialization.load_pem_private_key(key_pem, password=None)
            
        return cert, cert_pem, key
    except FileNotFoundError as e:
        print(f"Error: Missing credential file: {e.filename}")
        print("Did the CA server run and create the 'testuser' cert?")
        return None, None, None
    except Exception as e:
        print(f"Error loading credentials: {e}")
        return None, None, None

def sign_data(private_key, data):
    """Signs a piece of data with the user's private key."""
    signature = private_key.sign(
        data,
        padding.PKCS1v15(),
        hashes.SHA256()
    )
    return signature

def main():
    print("--- Kerberos Client Starting ---")
    
    # 1. Load credentials
    print("Loading credentials...")
    client_cert, client_cert_pem, client_key = load_credentials()
    if not client_key:
        return
    
    # 2. Prepare the AS_REQ payload
    print("Preparing AS_REQ...")
    # Create a timestamp in ISO 8601 format with UTC timezone
    timestamp_str = datetime.datetime.now(datetime.timezone.utc).isoformat()
    
    # 3. Create the canonical data to be signed
    # This MUST match what the server expects
    data_to_sign = {
        "principal": USER_PRINCIPAL,
        "timestamp": timestamp_str
    }
    # Create canonical JSON: no whitespace, keys sorted
    canonical_json = json.dumps(data_to_sign, sort_keys=True, separators=(",", ":")).encode('utf-8')
    
    # 4. Sign the canonical data
    print(f"Signing data: {canonical_json.decode('utf-8')}")
    signature = sign_data(client_key, canonical_json)
    
    # 5. Build the final JSON request
    request_data = {
        "type": "AS_REQ",
        "cert_pem": client_cert_pem.decode('utf-8'),
        "principal": USER_PRINCIPAL,
        "timestamp": timestamp_str,
        "signed_data": base64.b64encode(signature).decode('utf-8')
    }
    
    try:
        # 6. Connect to the KDC and send the request
        print(f"Connecting to KDC at {KDC_HOST}:{KDC_PORT}...")
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.connect((KDC_HOST, KDC_PORT))
            
            print("Sending AS_REQ...")
            sock.sendall(json.dumps(request_data).encode('utf-8'))
            
            # 7. Wait for the response
            print("Waiting for AS_REP...")
            response_raw = sock.recv(4096)
            if not response_raw:
                print("Server closed connection.")
                return

            response = json.loads(response_raw.decode('utf-8'))
            
            # 8. Print the server's response
            print("\n--- Server Response ---")
            print(json.dumps(response, indent=2))
            print("-------------------------")

            if response.get('status') == 'OK':
                print("\nAuthentication successful!")
                # TODO: Save the TGT and Session Key
            else:
                print(f"\nAuthentication failed: {response.get('message')}")

    except ConnectionRefusedError:
        print(f"Error: Connection refused. Is the KDC running at {KDC_HOST}:{KDC_PORT}?")
    except Exception as e:
        print(f"An error occurred: {e}")

if __name__ == "__main__":
    # Wait for the KDC to be ready
    print("Waiting 5 seconds for KDC to start...")
    time.sleep(5)
    main()