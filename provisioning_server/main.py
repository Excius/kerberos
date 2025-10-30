import os
import shutil
import sqlite3
from flask import Flask, request, jsonify
from kdc_server.database import get_db_conn
from config.config import PROVISIONING_SERVER_PORT, REALM

# --- Flask App Initialization ---
app = Flask(__name__)

# --- Configuration ---
PRIMARY_DB_PATH = '/app/db/primary/kdc.db'
REPLICA_DB_PATH = '/app/db/replica/kdc.db'
REPLICA_DB_DIR='/app/db/replica'


# Helper to get the primary DB connection
def get_primary_db_conn():
    """Connects to the primary KDC database."""
    if not os.path.exists(PRIMARY_DB_PATH):
        print(f"Error: Primary KDC database not found at {PRIMARY_DB_PATH}")
        raise FileNotFoundError("Primary KDC database not found.")
    return get_db_conn(PRIMARY_DB_PATH)


# TODO: Need to secure this endpoint only CA server can call it.

@app.route('/create-user', methods=['POST'])
def create_user():
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
        conn = get_db_conn()
        cursor = conn.cursor()
        
        # Insert the new user, linking them to their certificate subject
        # for 'pkinit' (certificate-based) authentication.
        cursor.execute(
            """
            INSERT INTO principals (principal_name, auth_type, cert_subject, cert_fingerprint, secret_key_b64)
            VALUES (?, 'pkinit', ?, ?, NULL)
            """,
            (principal_name, cert_subject, cert_fingerprint)
        )
        conn.commit()
        
        print(f"Successfully provisioned principal: {principal_name}")

        # After a successful user creation, trigger a sync
        # In a real system, this might be asynchronous
        sync_status = sync_replica_internal()
        print(f"Replica sync status: {sync_status}")


        return jsonify({
            "message": "User principal created successfully",
            "principal_name": principal_name,
        }), 201

    except sqlite3.IntegrityError as e:
        # This will happen if the principal_name or cert_subject already exists
        print(f"Error provisioning user (IntegrityError): {e}")
        return jsonify({
            "error": "Principal or certificate subject already exists",
            "details": str(e)
        }), 409 # 409 Conflict
    except Exception as e:
        print(f"Internal server error: {e}")
        return jsonify({"error": "An internal server error occurred"}), 500
    finally:
        if conn:
            conn.close()

@app.route("/sync-replica", methods=['POST'])
def sync_replica_endpoint():
    """
    Manually triggers a sync by copying the primary DB to the replica's volume.
    This endpoint can be called by an admin or a cron job.
    """
    print("Received manual sync request...")
    try:
        message = sync_replica_internal()
        return jsonify({"status": "ok", "message": message}), 200
    except Exception as e:
        print(f"Error during replica sync: {e}")
        return jsonify({"status": "error", "message": str(e)}), 500
    
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

if __name__ == '__main__':
    print("--- Starting Provisioning API Server ---")
    
    # Note: The 'primary-kdc' container must run first
    # to call 'init_kdc_db()' and create the database file.
    
    # Run the Flask server, making it accessible within the Docker network
    app.run(host='0.0.0.0', port=PROVISIONING_SERVER_PORT)

