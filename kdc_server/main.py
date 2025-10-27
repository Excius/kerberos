import argparse
import time
import socketserver
import json
import base64
import os
import sys
import datetime
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric import rsa


# We need to import the DB functions from the kdc_server module.
# This adds the parent directory to the Python path so we can import 'kdc_server'
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
try:
    from kdc_server.database import init_kdc_db, get_db_conn
except ImportError:
    print("Error: Could not import from 'kdc_server.database'.")
    print("Make sure 'kdc_server/database.py' exists.")
    sys.exit(1)


# --- Configuration ---
CA_CERT_PATH = "/app/data/ca_cert.pem" 

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
            # elif data.get('type') == 'TGS_REQ':
            #     self.handle_tgs_req(data) # TODO in a future step
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
            if now < client_cert.not_valid_before or now > client_cert.not_valid_after:
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
            
            conn = get_db_conn()
            cursor = conn.cursor()
            cursor.execute(
                "SELECT * FROM principals WHERE auth_type = 'pkinit' AND cert_fingerprint = ?",
                (cert_fingerprint,)
            )
            principal_row = cursor.fetchone()
            conn.close()
            
            if not principal_row:
                # fallback: try matching subject string (less preferred)
                cert_subject_str = client_cert.subject.rfc4514_string()
                conn = get_db_conn()
                cursor = conn.cursor()
                cursor.execute(
                    "SELECT * FROM principals WHERE auth_type = 'pkinit' AND cert_subject = ?",
                    (cert_subject_str,)
                )
                principal_row = cursor.fetchone()
                conn.close()

                if not principal_row:
                    return self.send_error("Unknown principal for presented certificate.")
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

            message_bytes = json.dumps(signed_fields, sort_keys=True, seperators=(",", ":")).encode('utf-8')
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
            if data["principal"] != principal_row['principal_name'] and data["principal"] != cert_principal:
                return self.send_error("Principal name does not match certificate or registered principal.")

            # Timestamp check (ISO parsing + timezone)
            ts = None
            try:
                ts = datetime.datetime.fromisoformat(data["timestamp"].replace("Z", "+00:00"))
            except Exception:
                return self.send_error("Invalid timestamp format.")

            if abs((datetime.datetime.now(datetime.timezone.utc) - ts).total_seconds()) > 300:
                return self.send_error("Timestamp is outside the allowed window (possible replay attack).")

        except Exception as e:
            return self.send_error(f"Post-verification checks failed: {e}")

        print("Signature principal and timestamp checks OK.")

        # --- All Checks Passed ---
        # User is authenticated. Now we generate the TGT.
        print(f"Successfully authenticated user: {data['principal']}")
        
        # TODO: Generate Session Key for the client
        # TODO: Generate TGT (contains session key, username, expiry)
        # TODO: Encrypt TGT with TGS secret key (from DB)
        # TODO: Encrypt Session Key with client's public key
        
        response = {
            "status": "OK",
            "message": f"Authentication successful for {data['principal']}.",
            "principal": data['principal']
            # TODO: Add the encrypted TGT and encrypted session key here
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
        
        # Start the TCP server
        socketserver.TCPServer.allow_reuse_address = True
        server = ThreadedTCPServer((host, port), KDCRequestHandler)
        print(f"KDC service listening on {host}:{port}")
        
        try:
            server.serve_forever() # This line blocks and runs the server
        except KeyboardInterrupt:
            print("\nKDC service shutting down.")
            server.shutdown()
        
    elif role == 'replica':
        # The replica KDC just loads the DB (which is synced by a script)
        print("Role is REPLICA.")
        # TODO: Implement database sync check
        # TODO: Start the main KDC listener loop (read-only)
        
        # NOTE: This logic will be almost identical to the primary,
        # but the handler will be in a "read-only" mode.
        print("Replica service is running (in idle mode for now).")
        try:
            while True:
                time.sleep(3600)
        except KeyboardInterrupt:
            print("Replica service shutting down.")
        
    else:
        print(f"Error: Unknown role '{role}'")
        return

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
        port = 8889
    else:
        print(f"Error: Unknown role '{args.role}'")
        sys.exit(1)
    
    # Start the KDC on the default Kerberos port (or any we choose)
    start_kdc(args.role, host='0.0.0.0', port=port)

