import socket
import json
import base64
import os
import datetime
import time
import sys
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding as asym_padding
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey

from config.config import REALM

# --- Configuration ---
CERT_DIR = "/app/certs"
USER_CERT_PATH = os.path.join(CERT_DIR, "testuser_cert.pem")
USER_KEY_PATH = os.path.join(CERT_DIR, "testuser_key.pem")

# This is our "ticket cache" - just a file
TICKET_CACHE_PATH = "/tmp/krb5cc_testuser" 

KDC_HOST = "localhost"
KDC_PORT = 8888
SERVICE_HOST = "localhost" # Service Server host
SERVICE_PORT = 8000             # Service Server port

USER_PRINCIPAL = f"testuser@{REALM}"
SERVICE_PRINCIPAL = f"host/service.server@{REALM}" # The service we want to access

# --- Crypto Helpers ---

def load_credentials():
    """Loads the user's certificate and private key."""
    try:
        with open(USER_CERT_PATH, "rb") as f:
            cert_pem = f.read()
            cert = x509.load_pem_x509_certificate(cert_pem)
        with open(USER_KEY_PATH, "rb") as f:
            key_pem = f.read()
            key = serialization.load_pem_private_key(key_pem, password=None)
        if not isinstance(key, RSAPrivateKey):
            raise TypeError("Key is not an RSA Private Key")
        return cert, cert_pem, key
    except FileNotFoundError as e:
        print(f"Error: Missing credential file: {e.filename}")
        print("Did the 'signup' script run successfully first?")
        return None, None, None
    except Exception as e:
        print(f"Error loading credentials: {e}")
        return None, None, None

def sign_data(private_key, data):
    """Signs a piece of data with the user's private key."""
    return private_key.sign(data, asym_padding.PKCS1v15(), hashes.SHA256())

def decrypt_with_private_key(private_key, ciphertext_b64):
    """Decrypts the session key using the user's private key."""
    ciphertext = base64.b64decode(ciphertext_b64)
    plaintext = private_key.decrypt(
        ciphertext,
        asym_padding.OAEP(
            mgf=asym_padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return plaintext

def encrypt_with_aes_gcm(data_to_encrypt, key):
    """Encrypts data using AES-GCM. Returns a base64 string (nonce + ciphertext)."""
    if isinstance(data_to_encrypt, str):
        data_to_encrypt = data_to_encrypt.encode('utf-8')
    nonce = os.urandom(12)
    aesgcm = AESGCM(key)
    ciphertext = aesgcm.encrypt(nonce, data_to_encrypt, None)
    return base64.b64encode(nonce + ciphertext).decode('utf-8')

def decrypt_with_aes_gcm(ciphertext_b64, key):
    """Decrypts an AES-GCM base64 string (nonce + ciphertext)."""
    if isinstance(ciphertext_b64, str):
        ciphertext_b64 = ciphertext_b64.encode('utf-8')
    ciphertext_with_nonce = base64.b64decode(ciphertext_b64)
    nonce = ciphertext_with_nonce[:12]
    ciphertext = ciphertext_with_nonce[12:]
    
    aesgcm = AESGCM(key)
    plaintext = aesgcm.decrypt(nonce, ciphertext, None)
    return plaintext # Returns bytes

# --- Socket Helper ---

def send_and_recv(host, port, request_data):
    """Helper function to connect, send, and receive a response."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.connect((host, port))
        sock.sendall(json.dumps(request_data).encode('utf-8'))
        response_raw = sock.recv(4096)
        if not response_raw:
            print("Server closed connection.")
            return None
        return json.loads(response_raw.decode('utf-8'))

# --- Kerberos Steps ---

def request_tgt(client_cert, client_cert_pem, client_key):
    """
    Performs the AS_REQ to get a Ticket-Granting Ticket (TGT).
    Returns True on success, False on failure.
    """
    print("\n--- Phase 1: Requesting TGT (AS_REQ) ---")
    
    # 1. Prepare payload
    timestamp_str = datetime.datetime.now(datetime.timezone.utc).isoformat()
    data_to_sign = {"principal": USER_PRINCIPAL, "timestamp": timestamp_str}
    canonical_json = json.dumps(data_to_sign, sort_keys=True, separators=(",", ":")).encode('utf-8')
    
    # 2. Sign and build request
    print(f"Signing data: {canonical_json.decode('utf-8')}")
    signature = sign_data(client_key, canonical_json)
    request_data = {
        "type": "AS_REQ",
        "cert_pem": client_cert_pem.decode('utf-8'),
        "principal": USER_PRINCIPAL,
        "timestamp": timestamp_str,
        "signed_data": base64.b64encode(signature).decode('utf-8')
    }
    
    try:
        # 3. Connect and send
        print(f"Connecting to KDC at {KDC_HOST}:{KDC_PORT}...")
        response = send_and_recv(KDC_HOST, KDC_PORT, request_data)
        if not response:
            return False

        # 4. Handle response
        if response.get('status') == 'OK':
            print("AS_REQ successful!")
            
            # 5. Decrypt session key
            encrypted_key_b64 = response['encrypted_session_key']
            session_key = decrypt_with_private_key(client_key, encrypted_key_b64)
            
            # 6. Save TGT and session key to cache
            cache_data = {
                "principal": response['principal'],
                "as_session_key": base64.b64encode(session_key).decode('utf-8'),
                "tgt": response['encrypted_tgt']
            }
            with open(TICKET_CACHE_PATH, 'w') as f:
                json.dump(cache_data, f)
            print(f"Saved TGT and session key to cache: {TICKET_CACHE_PATH}")
            return True
        else:
            print(f"Authentication failed: {response.get('message')}")
            return False
                
    except Exception as e:
        print(f"An error occurred during AS_REQ: {e}")
        return False

def request_service_ticket():
    """
    Performs the TGS_REQ to get a Service Ticket.
    Assumes request_tgt() has already run and populated the cache.
    """
    print("\n--- Phase 2: Requesting Service Ticket (TGS_REQ) ---")
    
    # 1. Load TGT and AS session key from cache
    try:
        with open(TICKET_CACHE_PATH, 'r') as f:
            cache_data = json.load(f)
        
        tgt = cache_data['tgt']
        as_session_key = base64.b64decode(cache_data['as_session_key'])
    except Exception as e:
        print(f"Error loading ticket cache: {e}")
        return False

    # 2. Create the Authenticator
    print("Creating authenticator...")
    auth_timestamp = datetime.datetime.now(datetime.timezone.utc).isoformat()
    authenticator_data = {
        "principal": USER_PRINCIPAL,
        "timestamp": auth_timestamp
    }
    authenticator_json = json.dumps(authenticator_data, sort_keys=True)
    
    # 3. Encrypt Authenticator with AS session key
    encrypted_authenticator = encrypt_with_aes_gcm(authenticator_json, as_session_key)
    
    # 4. Build the TGS_REQ
    tgs_req_data = {
        "type": "TGS_REQ",
        "tgt": tgt,
        "authenticator": encrypted_authenticator,
        "service_principal": SERVICE_PRINCIPAL
    }
    
    try:
        # 5. Connect and send to KDC
        print(f"Connecting to KDC at {KDC_HOST}:{KDC_PORT}...")
        response = send_and_recv(KDC_HOST, KDC_PORT, tgs_req_data)
        if not response:
            return False

        # 6. Handle response
        if response.get('status') == 'OK':
            print("TGS_REQ successful!")
            
            # 7. Decrypt the new SERVICE session key
            encrypted_key_b64 = response['encrypted_service_session_key']
            service_session_key_json_bytes = decrypt_with_aes_gcm(encrypted_key_b64, as_session_key)
            service_session_key_data = json.loads(service_session_key_json_bytes)
            service_session_key_b64 = service_session_key_data['service_session_key']
            
            # 8. Update cache with the new service ticket
            cache_data['service_ticket'] = response['service_ticket']
            cache_data['service_session_key'] = service_session_key_b64
            
            with open(TICKET_CACHE_PATH, 'w') as f:
                json.dump(cache_data, f)
            
            print(f"Received Service Ticket and saved to cache: {TICKET_CACHE_PATH}")
            return True
        else:
            print(f"TGS request failed: {response.get('message')}")
            return False

    except Exception as e:
        print(f"An error occurred during TGS_REQ: {e}")
        return False

def access_service():
    """
    Performs the AP_REQ to access the protected service.
    Assumes request_service_ticket() has populated the cache.
    """
    print("\n--- Phase 3: Accessing Protected Service (AP_REQ) ---")
    
    # 1. Load Service Ticket and Service Session Key from cache
    try:
        with open(TICKET_CACHE_PATH, 'r') as f:
            cache_data = json.load(f)
        
        service_ticket = cache_data['service_ticket']
        service_session_key = base64.b64decode(cache_data['service_session_key'])
    except Exception as e:
        print(f"Error loading service ticket from cache: {e}")
        return False

    # 2. Create the Authenticator for the service
    print("Creating service authenticator...")
    auth_timestamp = datetime.datetime.now(datetime.timezone.utc).isoformat()
    authenticator_data = {
        "principal": USER_PRINCIPAL,
        "timestamp": auth_timestamp
    }
    authenticator_json = json.dumps(authenticator_data, sort_keys=True)
    
    # 3. Encrypt Authenticator with SERVICE session key
    encrypted_authenticator = encrypt_with_aes_gcm(authenticator_json, service_session_key)
    
    # 4. Build the AP_REQ
    ap_req_data = {
        "type": "AP_REQ",
        "service_ticket": service_ticket,
        "authenticator": encrypted_authenticator
    }
    
    try:
        # 5. Connect and send to SERVICE SERVER
        print(f"Connecting to Service Server at {SERVICE_HOST}:{SERVICE_PORT}...")
        response = send_and_recv(SERVICE_HOST, SERVICE_PORT, ap_req_data)
        if not response:
            return False
            
        # 6. Handle response
        print("\n--- Service Server Response ---")
        print(json.dumps(response, indent=2))
        print("-------------------------------")
        
        if response.get('status') == 'OK':
            print("\nSuccessfully accessed protected service!")
            return True
        else:
            print(f"\nService access failed: {response.get('message')}")
            return False
            
    except ConnectionRefusedError:
        print(f"Error: Connection refused. Is the 'service-server' running at {SERVICE_HOST}:{SERVICE_PORT}?")
        return False
    except Exception as e:
        print(f"An error occurred during AP_REQ: {e}")
        return False

def main():
    print("--- Kerberos Client Full Flow Test ---")
    
    # 0. Load credentials
    print("Loading credentials...")
    client_cert, client_cert_pem, client_key = load_credentials()
    if not client_key:
        print("Halting: Could not load client credentials.")
        return
    
    # 1. Perform AS_REQ
    if not request_tgt(client_cert, client_cert_pem, client_key):
        print("Halting due to AS_REQ failure.")
        return

    # 2. Perform TGS_REQ
    if not request_service_ticket():
        print("Halting due to TGS_REQ failure.")
        return
        
    # 3. Perform AP_REQ
    if not access_service():
        print("Halting due to AP_REQ failure.")
        return
        
    print("\n✅ ✅ ✅ Full Kerberos flow (AS, TGS, AP) completed successfully! ✅ ✅ ✅")

if __name__ == "__main__":
    # Wait for all services to be ready
    print("Waiting 10 seconds for all services to start...")
    time.sleep(10)
    
    # Check if a signup is needed
    if not os.path.exists(USER_CERT_PATH) or not os.path.exists(USER_KEY_PATH):
        print("Credentials not found. Running signup script first...")
        # This assumes signup.py is in the same directory
        try:
            # We import and run the signup logic directly
            from client.signup import run_signup
            run_signup()
        except ImportError:
            print("Could not import signup script. Please run it manually.")
            sys.exit(1)
        except Exception as e:
            print(f"Signup script failed: {e}")
            sys.exit(1)
        
        print("Signup complete. Waiting 2s before authentication...")
        time.sleep(2)
    
    main()

