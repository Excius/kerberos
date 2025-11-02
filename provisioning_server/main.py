from functools import wraps
import os
import shutil
import sqlite3
import sys
from flask import Flask, request, jsonify
from kdc_server.database import get_db_conn
from config.config import PROVISIONING_SERVER_PORT, REALM

# --- Flask App Initialization ---
app = Flask(__name__)

INTERNAL_API_KEY = os.environ.get("INTERNAL_API_KEY")
if not INTERNAL_API_KEY:
    print("CRITICAL: INTERNAL_API_KEY environment variable not set.")
    sys.exit(1)


# --- Configuration ---
PRIMARY_DB_PATH = '/app/db/primary/kdc.db'
REPLICA_DB_PATH = '/app/db/replica/kdc.db'
REPLICA_DB_DIR='/app/db/replica'


# --- Security Decorator ---
def require_api_key(f):
    """
    Decorator to check for a valid API key in the 'Authorization' header.
    The header should look like: 'Authorization: Bearer <your-api-key>'
    """
    @wraps(f)
    def decorated_function(*args, **kwargs):
        auth_header = request.headers.get('Authorization')
        if not auth_header:
            return jsonify({"error": "Authorization header is missing"}), 401
        
        try:
            # Check for 'Bearer <key>' format
            auth_type, api_key = auth_header.split(' ')
            if auth_type != 'Bearer':
                raise ValueError()
        except ValueError:
            return jsonify({"error": "Invalid Authorization header format. Use 'Bearer <key>'."}), 401
        
        if api_key == INTERNAL_API_KEY:
            # Key is valid, proceed to the route
            return f(*args, **kwargs)
        else:
            # Key is invalid
            return jsonify({"error": "Invalid API key"}), 403
            
    return decorated_function


# Helper to get the primary DB connection
def get_primary_db_conn():
    """Connects to the primary KDC database."""
    if not os.path.exists(PRIMARY_DB_PATH):
        print(f"Error: Primary KDC database not found at {PRIMARY_DB_PATH}")
        raise FileNotFoundError("Primary KDC database not found.")
    return get_db_conn(PRIMARY_DB_PATH)

def sync_replica_internal():
    """Internal function to perform the database copy."""
    try:
        # Ensure replica directory exists
        os.makedirs(REPLICA_DB_DIR, exist_ok=True)
        
        # This is a simple file copy.
        shutil.copyfile(PRIMARY_DB_PATH, REPLICA_DB_PATH)
        
        message = f"Successfully synced {PRIMARY_DB_PATH} to {REPLICA_DB_PATH}"
        print(message)
        return message
        
    except Exception as e:
        message = f"Error during replica sync: {e}"
        print(message)
        return message
    

@app.route('/provision-new-user', methods=['POST'])
@require_api_key
def provision_new_user():
    """
    API endpoint to create a new user principal in the KDC database.
    This should be called by your signup logic (e.g., from the CA server)
    after a certificate has been successfully issued.
    
    Expects JSON payload:
    {
        "username": "newuser",
        "cert_subject": "CN=newuser,O=MyKerberosProject",
        "cert_fingerprint": "sha256_hex_fingerprint"
    }
    """
    data = request.get_json(silent=True) or {}
    username = data.get('username')
    cert_subject = data.get('cert_subject')
    cert_fingerprint = data.get('cert_fingerprint')

    if not username or not cert_subject:
        return jsonify({"error": "username and cert_subject are required"}), 400

    principal_name = f"{username}@{REALM}"
    
    conn = None
    try:
        conn = get_primary_db_conn()
        cursor = conn.cursor()
        
        # 1. Create the master user account
        cursor.execute(
            "INSERT INTO users (principal_name) VALUES (?)",
            (principal_name,)
        )
        user_id = cursor.lastrowid

        # 2. Add their first trusted device
        cursor.execute(
            """
            INSERT INTO devices (user_id, cert_fingerprint, cert_subject, status)
            VALUES (?, ?, ?, 'trusted')
            """,
            (user_id, cert_fingerprint, cert_subject)
        )
        conn.commit()
        
        print(f"Successfully provisioned NEW user: {principal_name} (UserID: {user_id})")
        sync_status = sync_replica_internal() # Sync after write
        
        return jsonify({
            "message": f"New user and first device provisioned. {sync_status}",
            "principal_name": principal_name,
            "user_id": user_id
        }), 201

    except sqlite3.IntegrityError as e:
        print(f"Error provisioning new user (IntegrityError): {e}")
        return jsonify({"error": "User principal or device fingerprint already exists"}), 409
    except Exception as e:
        print(f"Internal server error: {e}")
        return jsonify({"error": "An internal server error occurred"}), 500
    finally:
        if conn:
            conn.close()

@app.route('/add-device', methods=['POST'])
@require_api_key
def add_device():
    """
    Adds a new trusted device to an EXISTING user.
    This is called by the CA *after* an existing device has approved it.
    """
    data = request.get_json(silent=True) or {}
    principal_name = data.get('principal_name')
    cert_subject = data.get('cert_subject')
    cert_fingerprint = data.get('cert_fingerprint')

    if not principal_name or not cert_subject or not cert_fingerprint:
        return jsonify({"error": "principal_name, cert_subject, and cert_fingerprint are required"}), 400
    
    conn = None
    try:
        conn = get_primary_db_conn()
        cursor = conn.cursor()
        
        # 1. Find the existing user's ID
        cursor.execute(
            "SELECT user_id FROM users WHERE principal_name = ?", (principal_name,)
        )
        user_row = cursor.fetchone()
        
        if not user_row:
            return jsonify({"error": "User not found"}), 404
            
        user_id = user_row['user_id']
        
        # 2. Add the new trusted device
        cursor.execute(
            """
            INSERT INTO devices (user_id, cert_fingerprint, cert_subject, status)
            VALUES (?, ?, ?, 'trusted')
            """,
            (user_id, cert_fingerprint, cert_subject)
        )
        conn.commit()
        
        print(f"Successfully added new device to user: {principal_name}")
        sync_status = sync_replica_internal() # Sync after write
        
        return jsonify({
            "message": f"New device added successfully. {sync_status}",
            "principal_name": principal_name,
            "user_id": user_id
        }), 201

    except sqlite3.IntegrityError as e:
        print(f"Error adding device (IntegrityError): {e}")
        return jsonify({"error": "Device fingerprint already exists"}), 409
    except Exception as e:
        print(f"Internal server error: {e}")
        return jsonify({"error": "An internal server error occurred"}), 500
    finally:
        if conn:
            conn.close()

@app.route('/sync-replica', methods=['POST'])
@require_api_key
def sync_replica_endpoint():
    """Manually triggers a sync."""
    print("Received manual sync request...")
    try:
        message = sync_replica_internal()
        return jsonify({"status": "ok", "message": message}), 200
    except Exception as e:
        print(f"Error during replica sync: {e}")
        return jsonify({"status": "error", "message": str(e)}), 500

if __name__ == '__main__':
    print("--- Starting Provisioning API Server (Multi-Device) ---")
    if not os.path.exists(PRIMARY_DB_PATH):
        print(f"Warning: Primary DB {PRIMARY_DB_PATH} not found.")
    app.run(host='0.0.0.0', port=PROVISIONING_SERVER_PORT)


