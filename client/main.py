import socket
import json
import base64
import os
import datetime
import time
import sys
import asyncio
import websockets
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding as asym_padding
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey

# --- Configuration ---
# Add parent directory to path to import config
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
try:
    from config.config import (
        REALM, KDC_PORT, KDC_PRIMARY_PORT, KDC_REPLICA_PORT, SERVICE_SERVER_PORT
    )
except ImportError:
    print("Error: config/config.py not found. Please create it.")
    print("Using default values for testing.")
    KDC_PORT = 8888
    KDC_PRIMARY_PORT = 8888
    KDC_REPLICA_PORT = 8889
    SERVICE_SERVER_PORT = 6000

# Local paths for credentials (to be run from host)
CERT_DIR = os.path.join(os.getcwd(), "cert")
USER_CERT_PATH = os.path.join(CERT_DIR, "client.crt")
USER_KEY_PATH = os.path.join(CERT_DIR, "client.key")

# This is our "ticket cache" - just a file
TICKET_CACHE_PATH = "/tmp/krb5cc_testuser" 

# Service connection info
KDC_HOST_PRIMARY = "localhost"
KDC_HOST_REPLICA = "localhost"
SERVICE_HOST = "localhost" 

USER_PRINCIPAL = f"testuser@{REALM}"
SERVICE_PRINCIPAL = f"host/service.server@{REALM}"

# --- Crypto Helpers ---

def load_credentials():
    """Loads the user's certificate and private key from local ./cert dir."""
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
        print("Please run 'python client/signup.py' first.")
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
    """Helper function to connect, send, and receive a response via TCP."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.settimeout(5.0) # Set a timeout
        sock.connect((host, port))
        sock.sendall(json.dumps(request_data).encode('utf-8'))
        response_raw = sock.recv(4096)
        if not response_raw:
            print("Server closed connection.")
            return None
        return json.loads(response_raw.decode('utf-8'))

async def send_and_recv_ws(host, port, request_data):
    """Helper function to connect, send, and receive a response via WebSocket."""
    uri = f"ws://{host}:{port}"
    try:
        async with websockets.connect(uri) as websocket:
            await websocket.send(json.dumps(request_data))
            response_str = await websocket.recv()
            return json.loads(response_str)
    except Exception as e:
        print(f"WebSocket error: {e}")
        return None

# --- Kerberos Steps ---

async def request_tgt(client_cert, client_cert_pem, client_key, kdc_host, kdc_port):
    """
    Performs the AS_REQ to get a Ticket-Granting Ticket (TGT).
    """
    print(f"\n--- Phase 1: Requesting TGT (AS_REQ) from {kdc_host}:{kdc_port} ---")
    
    timestamp_str = datetime.datetime.now(datetime.timezone.utc).isoformat()
    data_to_sign = {"principal": USER_PRINCIPAL, "timestamp": timestamp_str}
    canonical_json = json.dumps(data_to_sign, sort_keys=True, separators=(",", ":")).encode('utf-8')
    
    print(f"Signing data: {canonical_json.decode('utf-8')}")
    signature = sign_data(client_key, canonical_json)
    request_data = {
        "type": "AS_REQ",
        "cert_pem": client_cert_pem.decode('utf-8'),
        "principal": USER_PRINCIPAL,
        "timestamp": timestamp_str,
        "signed_data": base64.b64encode(signature).decode('utf-8')
    }
    
    print(f"Connecting to KDC at {kdc_host}:{kdc_port}...")
    response = await send_and_recv_ws(kdc_host, kdc_port, request_data)
    if not response:
        return False

    if response.get('status') == 'OK':
        print("AS_REQ successful!")
        encrypted_key_b64 = response['encrypted_session_key']
        session_key = decrypt_with_private_key(client_key, encrypted_key_b64)
        
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

async def request_service_ticket(kdc_host, kdc_port):
    """
    Performs the TGS_REQ to get a Service Ticket.
    """
    print(f"\n--- Phase 2: Requesting Service Ticket (TGS_REQ) from {kdc_host}:{kdc_port} ---")
    
    try:
        with open(TICKET_CACHE_PATH, 'r') as f:
            cache_data = json.load(f)
        tgt = cache_data['tgt']
        as_session_key = base64.b64decode(cache_data['as_session_key'])
    except Exception as e:
        print(f"Error loading ticket cache: {e}"); return False

    auth_timestamp = datetime.datetime.now(datetime.timezone.utc).isoformat()
    authenticator_data = {"principal": USER_PRINCIPAL, "timestamp": auth_timestamp}
    authenticator_json = json.dumps(authenticator_data, sort_keys=True)
    encrypted_authenticator = encrypt_with_aes_gcm(authenticator_json, as_session_key)
    
    tgs_req_data = {
        "type": "TGS_REQ",
        "tgt": tgt,
        "authenticator": encrypted_authenticator,
        "service_principal": SERVICE_PRINCIPAL
    }
    
    print(f"Connecting to KDC at {kdc_host}:{kdc_port}...")
    response = await send_and_recv_ws(kdc_host, kdc_port, tgs_req_data)
    if not response:
        return False

    if response.get('status') == 'OK':
        print("TGS_REQ successful!")
        encrypted_key_b64 = response['encrypted_service_session_key']
        service_session_key_json_bytes = decrypt_with_aes_gcm(encrypted_key_b64, as_session_key)
        service_session_key_data = json.loads(service_session_key_json_bytes)
        service_session_key_b64 = service_session_key_data['service_session_key']
        
        cache_data['service_ticket'] = response['service_ticket']
        cache_data['service_session_key'] = service_session_key_b64
        
        with open(TICKET_CACHE_PATH, 'w') as f:
            json.dump(cache_data, f)
        print(f"Received Service Ticket and saved to cache: {TICKET_CACHE_PATH}")
        return True
    else:
        print(f"TGS request failed: {response.get('message')}")
        return False

async def access_service():
    """
    Performs the AP_REQ to access the protected service.
    """
    print("\n--- Phase 3: Accessing Protected Service (AP_REQ) ---")
    
    try:
        with open(TICKET_CACHE_PATH, 'r') as f:
            cache_data = json.load(f)
        service_ticket = cache_data['service_ticket']
        service_session_key = base64.b64decode(cache_data['service_session_key'])
    except Exception as e:
        print(f"Error loading service ticket from cache: {e}"); return False

    auth_timestamp = datetime.datetime.now(datetime.timezone.utc).isoformat()
    authenticator_data = {"principal": USER_PRINCIPAL, "timestamp": auth_timestamp}
    authenticator_json = json.dumps(authenticator_data, sort_keys=True)
    encrypted_authenticator = encrypt_with_aes_gcm(authenticator_json, service_session_key)
    
    ap_req_data = {
        "type": "AP_REQ",
        "service_ticket": service_ticket,
        "authenticator": encrypted_authenticator
    }
    
    try:
        print(f"Connecting to Service Server at {SERVICE_HOST}:{SERVICE_SERVER_PORT}...")
        response = await send_and_recv_ws(SERVICE_HOST, SERVICE_SERVER_PORT, ap_req_data)
        if not response:
            return False
            
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
        print(f"Error: Connection refused. Is 'service-server' running at {SERVICE_HOST}:{SERVICE_SERVER_PORT}?")
        return False
    except Exception as e:
        print(f"An error occurred during AP_REQ: {e}")
        return False

async def request_service_list(kdc_host, kdc_port):
    """
    Requests the list of available services from the KDC.
    """
    print(f"\n--- Requesting Service List from {kdc_host}:{kdc_port} ---")
    
    request_data = {"type": "LIST_SERVICES"}
    
    response = await send_and_recv_ws(kdc_host, kdc_port, request_data)
    if response and response.get('status') == 'OK':
        services = response.get('services', [])
        print("Available services:")
        for service in services:
            name = service.get("name", "Unknown")
            url = service.get("url", "N/A")
            desc = service.get("description", "No description")
            print(f"  - {name}: {desc} (URL: {url})")
        return services
    else:
        print(f"Failed to list services: {response}")
        return []

async def run_full_flow(kdc_host, kdc_port):
    """Runs the complete AS -> TGS -> AP flow against a specific KDC."""
    
    # 0. Load credentials
    print("Loading credentials...")
    client_cert, client_cert_pem, client_key = load_credentials()
    if not client_key:
        print("Halting: Could not load client credentials.")
        return False
    
    # 1. Perform AS_REQ
    if not await request_tgt(client_cert, client_cert_pem, client_key, kdc_host, kdc_port):
        print("Halting due to AS_REQ failure.")
        return False

    # List available services
    services = await request_service_list(kdc_host, kdc_port)
    if not services:
        print("No services available.")
        return False

    # 2. Perform TGS_REQ
    if not await request_service_ticket(kdc_host, kdc_port):
        print("Halting due to TGS_REQ failure.")
        return False
        
    # 3. Perform AP_REQ
    if not await access_service():
        print("Halting due to AP_REQ failure.")
        return False
        
    print(f"\n✅ ✅ ✅ Full flow (AS, TGS, AP) via {kdc_host}:{kdc_port} succeeded! ✅ ✅ ✅")
    return True

if __name__ == "__main__":
    # Wait for all services to be ready
    print("Waiting 10 seconds for all services to start...")
    time.sleep(10)
    
    # Check if a signup is needed
    if not os.path.exists(USER_CERT_PATH) or not os.path.exists(USER_KEY_PATH):
        print("Credentials not found. Running signup script first...")
        try:
            # We import and run the signup logic directly
            from client.signup import run_signup
            run_signup()
        except ImportError:
            print("Could not import signup script. Please run 'python client/signup.py' manually.")
            sys.exit(1)
        except Exception as e:
            print(f"Signup script failed: {e}")
            sys.exit(1)
        
        print("Signup complete. Waiting 2s before authentication...")
        time.sleep(2)
    
    # --- Test 1: Authenticate against Primary KDC ---
    print("\n\n" + "="*50)
    print("TEST 1: Authenticating against PRIMARY KDC")
    print("="*50)
    try:
        success_primary = asyncio.run(run_full_flow(KDC_HOST_PRIMARY, KDC_PRIMARY_PORT))
    except ConnectionRefusedError:
        print(f"Error: Connection refused. Is 'primary-kdc' running at {KDC_HOST_PRIMARY}:{KDC_PRIMARY_PORT}?")
        success_primary = False
    except Exception as e:
        print(f"An unexpected error occurred: {e}")
        success_primary = False

    if not success_primary:
        print("\nPrimary KDC test failed. Skipping failover test.")
        sys.exit(1)

    # --- Test 2: Authenticate against Replica KDC (Failover Test) ---
    print("\n\n" + "="*50)
    print("TEST 2: Authenticating against REPLICA KDC (Failover Test)")
    print("="*50)
    try:
        success_replica = asyncio.run(run_full_flow(KDC_HOST_REPLICA, KDC_REPLICA_PORT))
    except ConnectionRefusedError:
        print(f"Error: Connection refused. Is 'replica-kdc' running at {KDC_HOST_REPLICA}:{KDC_REPLICA_PORT}?")
        success_replica = False
    except Exception as e:
        print(f"An unexpected error occurred: {e}")
        success_replica = False

    if not success_replica:
        print("\nHigh-Availability test FAILED.")
    else:
        print("\nHigh-Availability test PASSED. Both KDCs are working.")

