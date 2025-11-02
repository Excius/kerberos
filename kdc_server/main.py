import argparse
import socketserver
import json
import base64
import os
import sys
import datetime
import secrets
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric import rsa

from config.config import REALM, SERVICE_TICKET_LIFETIME_SECONDS, TGT_LIFETIME_SECONDS, TIMESTAMP_WINDOW_SECONDS
from provisioning_server.main import REPLICA_DB_PATH


# We need to import the DB functions from the kdc_server module.
# This adds the parent directory to the Python path so we can import 'kdc_server'
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
try:
    from kdc_server.database import init_kdc_db, get_db_conn, DB_PATH
except ImportError:
    print("Error: Could not import from 'kdc_server.database'.")
    print("Make sure 'kdc_server/database.py' exists.")
    sys.exit(1)


# --- Configuration ---
CA_CERT_PATH = "/app/data/ca_cert.pem"

# --- Encryption Helpers ---

def encrypt_with_aes_gcm(data_to_encrypt, key):
    """Encrypts the TGT data with the given key. Returns the base64 string."""

    nonce = os.urandom(12) # 12 bytes is standard for GCM
    aesgcm = AESGCM(key)
    ciphertext = aesgcm.encrypt(nonce, data_to_encrypt.encode('utf-8'), None)

    # we must store the nonce with the ciphertext for decryption
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


def encrypt_with_public_key(data_to_encrpyt, public_key):
    """Encrypts data with the given RSA public key """
    if not isinstance(public_key, rsa.RSAPublicKey):
        raise ValueError("Provided key is not an RSA public key.")
    
    ciphertext = public_key.encrypt(
        data_to_encrpyt,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return base64.b64encode(ciphertext).decode('utf-8')

# --- KDC Request Handler ---

class KDCRequestHandler(socketserver.BaseRequestHandler):
    """
    Handles incoming TCP requests for the KDC (both AS and TGS).
    A new instance is created for each connection, and 'handle' is called.
    """
    def setup(self):
        """Called before handle()"""
        print(f"\nNew connection from {self.client_address}")
        self.ca_cert = self.load_ca_cert()

    def load_ca_cert(self):
        """Loads the CA's public certificate to build the chain of trust."""
        if not os.path.exists(CA_CERT_PATH):
            print(f"CRITICAL: CA Certificate not found at {CA_CERT_PATH}")
            return None
        try:
            with open(CA_CERT_PATH, "rb") as f:
                ca_cert = x509.load_pem_x509_certificate(f.read())
            print("Loaded CA certificate successfully.")
            return ca_cert
        except Exception as e:
            print(f"Error loading CA certificate: {e}")
            return None

    def handle(self):
        """Main handler for all incoming requests."""
        if not self.ca_cert:
            self.send_error("KDC is not properly configured (Missing CA)")
            return

        try:
            # 1. Receive data from the client
            raw_data = self.request.recv(4096).strip()
            if not raw_data:
                print("Client disconnected without sending data.")
                return
            
            # 2. Parse the request (we are using JSON for simplicity)
            data = json.loads(raw_data.decode('utf-8'))
            
            # 3. Route the request based on its type
            if data.get('type') == 'AS_REQ':
                self.handle_as_req(data)
            elif data.get('type') == 'TGS_REQ':
                self.handle_tgs_req(data)
            else:
                self.send_error("Invalid request type")
        
        except json.JSONDecodeError:
            self.send_error("Invalid JSON format")
        except Exception as e:
            print(f"An error occurred: {e}")
            self.send_error(f"Internal server error: {e}")

    def handle_as_req(self, data):
        """
        Handles the Authentication Server (AS) request (PKINIT).
        
        Handles AS_REQ.
        Expects JSON fields:
            - cert_pem: PEM certificate string
            - principal: "user@REALM"
            - timestamp: ISO8601 string
            - signed_data: base64 signature over canonical JSON of {principal, timestamp}
        """
        print("Handling AS_REQ...")
        
        # 1. Decode Certificate and Signature
        try:
            cert_pem = data['cert_pem'].encode('utf-8')
            signed_b64 = data['signed_data']
            if isinstance(signed_b64, str):
                signed_b64 = signed_b64.encode('utf-8')
            signed_data = base64.b64decode(signed_b64)
            client_cert = x509.load_pem_x509_certificate(cert_pem)
        except Exception as e:
            return self.send_error(f"Invalid request format: {e}")

        # 2. Verify Certificate Trust Chain
        try:
            # Ensure CA certificate is loaded
            if not self.ca_cert:
                return self.send_error("CA certificate not loaded.")
            
            # Check validity dates
            now = datetime.datetime.now(datetime.timezone.utc)
            if now < client_cert.not_valid_before_utc or now > client_cert.not_valid_after_utc:
                return self.send_error("Certificate is not currently valid (expired or not yet valid).")

            # Ensure issuer matches your CA
            if client_cert.issuer != self.ca_cert.subject:
                return self.send_error("Certificate issuer is not trusted.")

            ca_public_key = self.ca_cert.public_key()
            if not isinstance(ca_public_key, rsa.RSAPublicKey):
                return self.send_error("CA certificate must use RSA public key.")
            
            if client_cert.signature_hash_algorithm is None:
                return self.send_error("Unsupported signature algorithm.")

            try:
                ca_public_key.verify(
                    signature=client_cert.signature,
                    data=client_cert.tbs_certificate_bytes,
                    padding=padding.PKCS1v15(),
                    algorithm=client_cert.signature_hash_algorithm
                )
            except InvalidSignature:
                return self.send_error("Certificate signature is invalid.")

            # Simplified check: Is the certificate's issuer our CA?= self.
            if client_cert.issuer != self.ca_cert.subject:
                return self.send_error("Certificate issuer is not trusted.")
            
            # TODO: Add check for certificate revocation (CRL)
            
            print("Certificate trust OK.")
        except Exception as e:
            return self.send_error(f"Certificate trust check failed: {e}")

        # 3. Look up user in KDC Database
        try:
            cert_fingerprint = client_cert.fingerprint(hashes.SHA256()).hex()
            
            conn = get_db_conn(self.db_path)
            cursor = conn.cursor()
            cursor.execute(
                """
                SELECT u.principal_name 
                FROM devices d
                JOIN users u ON d.user_id = u.user_id
                WHERE d.cert_fingerprint = ? AND d.status = 'trusted'
                """,
                (cert_fingerprint,)
            )
            principal_row = cursor.fetchone()
            
            if not principal_row:
                return self.send_error("Unknown or untrusted device for presented certificate.")
            
            principal_name = principal_row['principal_name']
            
            # Fetch TGS secret key from the new table
            cursor.execute(f"SELECT secret_key_b64 FROM service_keys WHERE principal_name = 'tgs@{REALM}'")
            tgs_row = cursor.fetchone()
            conn.close()
            
            if not tgs_row:
                return self.send_error("KDC is misconfigured: TGS principal not found.")
            
            tgs_secret_key = base64.b64decode(tgs_row['secret_key_b64'])

        except Exception as e:
            return self.send_error(f"Database lookup failed: {e}")

        # 4. Verify Signature (Proof of Possession)
        try:

            client_public_key = client_cert.public_key()
            if not isinstance(client_public_key, rsa.RSAPublicKey):
                return self.send_error("CA certificate must use RSA public key.")
            
            signed_fields = {
                "principal": data["principal"],
                "timestamp": data["timestamp"]
            }

            message_bytes = json.dumps(signed_fields, sort_keys=True, separators=(",", ":")).encode('utf-8')
            # use separators to avoid whitespace differences

            client_public_key.verify(
                signed_data, # The signature
                message_bytes, # The original data
                padding.PKCS1v15(),
                hashes.SHA256()
            )
            print("Signature verified (Proof of possession OK).")
        except InvalidSignature:
            return self.send_error("Invalid signature. Proof of possession failed.")
        except Exception as e:
            return self.send_error(f"Signature verification error: {e}")
        

        # --- 5. Check principal binding and timestamp ---
        try:
            cert_cn_attr = client_cert.subject.get_attributes_for_oid(x509.NameOID.COMMON_NAME)
            cert_principal = cert_cn_attr[0].value if cert_cn_attr else None

            # Verify principal matches cert binding or DB canonical name
            if data["principal"] != principal_name and data["principal"] != cert_principal:
                return self.send_error("Principal name does not match certificate or registered principal.")

            # Timestamp check (ISO parsing + timezone)
            ts = None
            try:
                ts = datetime.datetime.fromisoformat(data["timestamp"].replace("Z", "+00:00"))
            except Exception:
                return self.send_error("Invalid timestamp format.")

            if abs((datetime.datetime.now(datetime.timezone.utc) - ts).total_seconds()) > TIMESTAMP_WINDOW_SECONDS:
                return self.send_error("Timestamp is outside the allowed window (possible replay attack).")

        except Exception as e:
            return self.send_error(f"Post-verification checks failed: {e}")

        print("Signature principal and timestamp checks OK.")

        # --- All Checks Passed ---
        # User is authenticated. Now we generate the TGT.

        try:
        
            # Generate Session Key for the client
            session_key = secrets.token_bytes(32)

            # Got the client's public key for encrypting the session key
            client_public_key = client_cert.public_key()
            if not isinstance(client_public_key, rsa.RSAPublicKey):
                return self.send_error("CA certificate must use RSA public key.")
            
            # Generate TGT (contains session key, username, expiry)
            tgt_expiry = datetime.datetime.now(datetime.timezone.utc)+ datetime.timedelta(seconds=TGT_LIFETIME_SECONDS)

            tgt_data = {
                "session_key": base64.b64encode(session_key).decode('utf-8'),
                "principal": principal_row['principal_name'],
                "expiry_time": tgt_expiry.isoformat()
            }

            tgt_data_json = json.dumps(tgt_data, sort_keys=True)

            # Encrypt TGT data with TGS secret key
            encrypted_tgt = encrypt_with_aes_gcm(tgt_data_json, tgs_secret_key)
            # Encrypt Session Key with client's public key
            encrypted_session_key = encrypt_with_public_key(session_key, client_public_key)
        except Exception as e:
            return self.send_error(f"Error generating TGT: {e}")
        
        print(f"Successfully authenticated user: {data['principal']}")

        response = {
            "status": "OK",
            "message": f"Authentication successful for {principal_row['principal_name']}.",
            "principal": principal_row['principal_name'],
            "encrypted_tgt": encrypted_tgt,
            "encrypted_session_key": encrypted_session_key,
        }
        self.send_response(response)

    # --- TGS Request Handler ---
    def handle_tgs_req(self, data):
        """
        Handles the Ticket Granting Server (TGS) request.
        
        Expects JSON:
        {
            "type": "TGS_REQ",
            "tgt": "...",             // TGT from AS
            "authenticator": "...",   // Encrypted authenticator
            "service_principal": "..." // e.g., "host/service.server@YOUR_REALM"
        }
        """
        print("Handling TGS_REQ...")

        # 1. Get TGS secret key from DB
        try:
            conn = get_db_conn(self.db_path)
            cursor = conn.cursor()
            cursor.execute(f"SELECT secret_key_b64 FROM service_keys WHERE principal_name = 'tgs@{REALM}'")
            tgs_row = cursor.fetchone()
            conn.close()
            if not tgs_row:
                return self.send_error("KDC misconfigured: TGS principal not found.")
            tgs_secret_key = base64.b64decode(tgs_row['secret_key_b64'])
        except Exception as e:
            return self.send_error(f"Failed to retrieve TGS key: {e}")
        
        # 2. Decrypt the TGT
        try:
            tgt_json = decrypt_with_aes_gcm(data['tgt'], tgs_secret_key)
            tgt_data = json.loads(tgt_json)

            # Check the TGT expiration
            expiry_time = datetime.datetime.fromisoformat(tgt_data['expiry_time'])
            if datetime.datetime.now(datetime.timezone.utc) > expiry_time:
                return self.send_error("TGT has expired.")
            
            as_session_key = base64.b64decode(tgt_data['session_key'])
            principal_from_tgt = tgt_data['principal']

        except Exception as e:
            return self.send_error(f"Failed to decrypt TGT: {e}")
        
        # 3. Decrypt the Authenticator
        try:
            auth_json = decrypt_with_aes_gcm(data['authenticator'], as_session_key)
            auth_data = json.loads(auth_json)

            # Check timestamp freshness
            auth_ts = datetime.datetime.fromisoformat(auth_data['timestamp'].replace("Z", "+00:00"))
            if abs((datetime.datetime.now(datetime.timezone.utc) - auth_ts).total_seconds()) >TIMESTAMP_WINDOW_SECONDS:
                return self.send_error("Authenticator timestamp is outside the allowed window (possible replay attack).")
            
            # Check if principal in TGT matches principal in Authenticator
            if auth_data['principal'] != principal_from_tgt:
                return self.send_error("Principal in Authenticator does not match TGT principal.")

            # TODO: Implement a replay cache to prevent reuse of this exact Authenticator

            print("Authenticator verified.")

        except Exception as e:
            return self.send_error(f"Failed to decrypt Authenticator: {e}")

        # 4. Get requested Service's secret key from DB
        try:
            service_principal = data['service_principal']
            conn = get_db_conn(self.db_path)
            cursor = conn.cursor()
            cursor.execute("SELECT secret_key_b64 FROM service_keys WHERE principal_name = ?", (service_principal,))
            service_row = cursor.fetchone()
            conn.close()
            
            if not service_row:
                return self.send_error(f"Unknown service principal: {service_principal}")
            service_secret_key = base64.b64decode(service_row['secret_key_b64'])

        except Exception as e:
            return self.send_error(f"Failed to retrieve service key: {e}")
        
        # --- All Check passe, Generating Service Ticket ---
        print(f"TGS check passed. Generating Service Ticket for {principal_from_tgt} to access {service_principal}")
        try:
            # 1. Generate a new Session Key (for Client-Service communication)
            service_session_key = os.urandom(32) # 32-byte (256-bit) key

            # 2. Create Service Tickert data (for the Service Server)
            ticket_expiry = datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(seconds = SERVICE_TICKET_LIFETIME_SECONDS)
            service_ticket_data = {
                "session_key": base64.b64encode(service_session_key).decode('utf-8'),
                "principal_name": principal_from_tgt,
                "expiry_time": ticket_expiry.isoformat()
            }

            service_ticket_json = json.dumps(service_ticket_data, sort_keys=True)

            # 3. Encrypt Service Ticket with Service's secret key
            encrypted_service_ticket = encrypt_with_aes_gcm(service_ticket_json, service_secret_key)

            # 4. Encrypt the new session key with the AS session key (for the client)
            client_response_data={
                "service_session_key": base64.b64encode(service_session_key).decode('utf-8'),
                "service_principal": service_principal,
                "expiry_time": ticket_expiry.isoformat()
            }

            client_response_json = json.dumps(client_response_data, sort_keys=True)
            encrypted_client_response = encrypt_with_aes_gcm(client_response_json, as_session_key)

        except Exception as e:
            return self.send_error(f"Error generating Service Ticket: {e}")
        
        # 5. Send response to client
        response = {
            "status": "OK",
            "service_ticket": encrypted_service_ticket,
            "encrypted_service_session_key": encrypted_client_response
        }

        self.send_response(response)


    def send_error(self, message):
        """Sends a JSON error message to the client."""
        print(f"Error: {message}")
        try:
            self.send_response({"status": "ERROR", "message": message})
        except Exception as e:
            print(f"Failed to send error response: {e}")

    def send_response(self, data):
        """Sends a JSON response to the client."""
        response_bytes = json.dumps(data).encode('utf-8')
        self.request.sendall(response_bytes)

# --- Server Class ---

class ThreadedTCPServer(socketserver.ThreadingMixIn, socketserver.TCPServer):
    """
    A multi-threaded TCP server.
    ThreadingMixIn ensures each connection is handled in a new thread.
    """
    pass

# --- Main Functions ---

def start_kdc(role, host='0.0.0.0', port=8888):
    """Starts the KDC in the specified role."""
    print(f"--- Starting KDC Server (Role: {role}) ---")
    
    if role == 'primary':
        # The primary KDC is responsible for initializing the database
        print("Role is PRIMARY. Initializing database...")
        init_kdc_db()
        db_path = DB_PATH
        
    elif role == 'replica':
        # The replica KDC just loads the DB (which is synced by a script)
        print("Role is REPLICA.")
        db_path = REPLICA_DB_PATH
        # We check if the DB file exists, which implies it has been synced at least once.
        if not os.path.exists(db_path):
            print(f"WARNING: Replica database file not found at {db_path}.")
            print("Waiting for provisioning server to sync...")
            # The server will still start, but authentication will fail
            # until the database file is copied into its volume by the
            # provisioning_server's /sync-replica endpoint.
        else:
            print("Replica database file found. Ready to serve read-only requests.")
        
    else:
        print(f"Error: Unknown role '{role}'")
        return

    # Set the db_path for the handler
    KDCRequestHandler.db_path = db_path

    # Both Primary and Replica run the same listener service
    socketserver.TCPServer.allow_reuse_address = True
    server = ThreadedTCPServer((host, port), KDCRequestHandler)
    print(f"KDC service listening on {host}:{port}")
    
    try:
        server.serve_forever() # This line blocks and runs the server
    except KeyboardInterrupt:
        print("\nKDC service shutting down.")
        server.shutdown()


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Kerberos KDC Server")
    parser.add_argument(
        '--role',
        type=str,
        required=True,
        choices=['primary', 'replica'],
        help="The role of this KDC instance (primary or replica)"
    )
    args = parser.parse_args()
    
    if args.role == 'primary':
        port = 8888
    elif args.role == 'replica':
        port = 8888
    else:
        print(f"Error: Unknown role '{args.role}'")
        sys.exit(1)
    
    # Start the KDC on the default Kerberos port (or any we choose)
    start_kdc(args.role, host='0.0.0.0', port=port)

