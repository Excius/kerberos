import socketserver
import json
import base64
import datetime
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.exceptions import InvalidTag

from config.config import SERVICE_SECRET_KEY_B64, SERVICE_SERVER_PORT, SERVICE_TICKET_LIFETIME_SECONDS

# --- Configuration ---
# This MUST match the key in kdc_server/database.py
if( not SERVICE_SECRET_KEY_B64 ):
    raise ValueError("SERVICE_SECRET_KEY_B64 is not set")
SERVICE_SECRET_KEY = base64.b64decode(SERVICE_SECRET_KEY_B64)

# --- Crypto Helper ---

def decrypt_with_aes_gcm(ciphertext_b64, key):
    """Decrypts an AES-GCM base64 string (nonce + ciphertext)."""
    try:
        if isinstance(ciphertext_b64, str):
            ciphertext_b64 = ciphertext_b64.encode('utf-8')
        
        ciphertext_with_nonce = base64.b64decode(ciphertext_b64)
        nonce = ciphertext_with_nonce[:12]
        ciphertext = ciphertext_with_nonce[12:]
        
        aesgcm = AESGCM(key)
        plaintext = aesgcm.decrypt(nonce, ciphertext, None)
        return plaintext # Returns bytes
    except InvalidTag:
        print("Error: Failed to decrypt. Key is incorrect or ciphertext is corrupt.")
        raise
    except Exception as e:
        print(f"Error during AES decryption: {e}")
        raise

# --- Service Request Handler ---

class ServiceRequestHandler(socketserver.BaseRequestHandler):
    """
    Handles incoming TCP requests for the protected service.
    """
    def setup(self):
        print(f"\nNew connection from {self.client_address}")

    def handle(self):
        try:
            # 1. Receive data from the client
            raw_data = self.request.recv(4096).strip()
            if not raw_data:
                print("Client disconnected without sending data.")
                return
            
            # 2. Parse the AP_REQ (we are using JSON)
            data = json.loads(raw_data.decode('utf-8'))
            
            # 3. Route the request
            if data.get('type') == 'AP_REQ':
                self.handle_ap_req(data)
            else:
                self.send_error("Invalid request type")
        
        except json.JSONDecodeError:
            self.send_error("Invalid JSON format")
        except Exception as e:
            print(f"An error occurred: {e}")
            self.send_error(f"Internal server error: {e}")

    def handle_ap_req(self, data):
        """
        Handles the Application (AP) request.
        
        Expected JSON:
        {
            "type": "AP_REQ",
            "service_ticket": "...", // Encrypted with service's secret key
            "authenticator": "..."  // Encrypted with service_session_key
        }
        """
        print("Handling AP_REQ...")

        # 1. Decrypt the Service Ticket
        try:
            print("Decrypting Service Ticket...")
            service_ticket_json = decrypt_with_aes_gcm(data['service_ticket'], SERVICE_SECRET_KEY)
            service_ticket_data = json.loads(service_ticket_json.decode('utf-8'))
            
            # 2. Validate Service Ticket
            expiry_time = datetime.datetime.fromisoformat(service_ticket_data['expiry_time'])
            if datetime.datetime.now(datetime.timezone.utc) > expiry_time:
                return self.send_error("Service Ticket has expired.")
                
            service_session_key = base64.b64decode(service_ticket_data['session_key'])
            principal_from_ticket = service_ticket_data['principal_name']
            
            print(f"Service Ticket validated for principal: {principal_from_ticket}")

        except Exception as e:
            return self.send_error(f"Failed to decrypt or validate Service Ticket: {e}")

        # 3. Decrypt the Authenticator
        try:
            print("Decrypting Authenticator...")
            authenticator_json = decrypt_with_aes_gcm(data['authenticator'], service_session_key)
            auth_data = json.loads(authenticator_json.decode('utf-8'))

            # 4. Validate Authenticator
            auth_ts = datetime.datetime.fromisoformat(auth_data['timestamp'].replace("Z", "+00:00"))
            if abs((datetime.datetime.now(datetime.timezone.utc) - auth_ts).total_seconds()) > SERVICE_TICKET_LIFETIME_SECONDS:
                return self.send_error("Authenticator timestamp is outside the allowed window (replay attack).")
                
            # Final check: Does the user in the ticket match the user in the authenticator?
            if auth_data['principal'] != principal_from_ticket:
                return self.send_error("Authenticator principal does not match ticket principal.")
                
            # TODO: Implement a replay cache for authenticators
            
            print("Authenticator validated.")

        except Exception as e:
            return self.send_error(f"Failed to decrypt or validate Authenticator: {e}")

        # --- All Checks Passed ---
        print(f"Successfully authenticated user: {principal_from_ticket}")
        
        response = {
            "status": "OK",
            "message": f"Welcome {principal_from_ticket}! You have successfully accessed the protected service.",
            "protected_data": "Here is your secret data: 123-456-789"
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
    """A multi-threaded TCP server."""
    pass

# --- Main Functions ---

def start_service(host='0.0.0.0', port=8000):
    """Starts the Service Server."""
    print(f"--- Starting Protected Service Server ---")
    
    socketserver.TCPServer.allow_reuse_address = True
    server = ThreadedTCPServer((host, port), ServiceRequestHandler)
    print(f"Protected service listening on {host}:{port}")
    
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nService server shutting down.")
        server.shutdown()

if __name__ == "__main__":
    start_service(host='0.0.0.0', port=SERVICE_SERVER_PORT)

