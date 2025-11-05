import json
import base64
import datetime
import asyncio
import websockets
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

async def handle_ap_req(data, websocket):
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
            return await websocket.send(json.dumps({"status": "ERROR", "message": "Service Ticket has expired."}))
            
        service_session_key = base64.b64decode(service_ticket_data['session_key'])
        principal_from_ticket = service_ticket_data['principal_name']
        
        print(f"Service Ticket validated for principal: {principal_from_ticket}")

    except Exception as e:
        return await websocket.send(json.dumps({"status": "ERROR", "message": f"Failed to decrypt or validate Service Ticket: {e}"}))

    # 3. Decrypt the Authenticator
    try:
        print("Decrypting Authenticator...")
        authenticator_json = decrypt_with_aes_gcm(data['authenticator'], service_session_key)
        auth_data = json.loads(authenticator_json.decode('utf-8'))

        # 4. Validate Authenticator
        auth_ts = datetime.datetime.fromisoformat(auth_data['timestamp'].replace("Z", "+00:00"))
        if abs((datetime.datetime.now(datetime.timezone.utc) - auth_ts).total_seconds()) > SERVICE_TICKET_LIFETIME_SECONDS:
            return await websocket.send(json.dumps({"status": "ERROR", "message": "Authenticator timestamp is outside the allowed window (replay attack)."}))
            
        # Final check: Does the user in the ticket match the user in the authenticator?
        if auth_data['principal'] != principal_from_ticket:
            return await websocket.send(json.dumps({"status": "ERROR", "message": "Authenticator principal does not match ticket principal."}))
            
        # TODO: Implement a replay cache for authenticators
        
        print("Authenticator validated.")

    except Exception as e:
        return await websocket.send(json.dumps({"status": "ERROR", "message": f"Failed to decrypt or validate Authenticator: {e}"}))

    # --- All Checks Passed ---
    print(f"Successfully authenticated user: {principal_from_ticket}")
    
    response = {
        "status": "OK",
        "message": f"Welcome {principal_from_ticket}! You have successfully accessed the protected service.",
        "protected_data": "Here is your secret data: 123-456-789"
    }
    await websocket.send(json.dumps(response))



# --- Main Functions ---

async def start_service():
    """Starts the Service Server."""
    print(f"--- Starting Protected Service Server ---")

    async def handle_connection(websocket):
        print(f"\nNew WebSocket connection from {websocket.remote_address}")
        
        try:
            message = await websocket.recv()
            data = json.loads(message)
            
            if data.get('type') == 'health_check':
                await websocket.send(json.dumps({"status": "OK"}))
                return
            
            if data.get('type', '').strip().upper() == 'AP_REQ':
                await handle_ap_req(data, websocket)
            else:
                await websocket.send(json.dumps({"status": "ERROR", "message": f"Invalid request type: {data}"}))
        
        except json.JSONDecodeError:
            await websocket.send(json.dumps({"status": "ERROR", "message": "Invalid JSON format"}))
        except Exception as e:
            print(f"An error occurred: {e}")
            await websocket.send(json.dumps({"status": "ERROR", "message": f"Internal server error: {e}"}))

    async with websockets.serve(handle_connection, "0.0.0.0", SERVICE_SERVER_PORT, origins=None):
        print(f"Protected service listening on 0.0.0.0:{SERVICE_SERVER_PORT}")
        await asyncio.Future()  # run forever


if __name__ == "__main__":
    asyncio.run(start_service())

