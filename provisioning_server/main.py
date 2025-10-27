import os
import sqlite3
import sys
from flask import Flask, request, jsonify
from config.config import YOUR_REALM

# --- Setup Python Path ---
# This adds the parent directory (your project root) to the Python path.
# It allows us to import the database functions from the 'kdc_server' directory.
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
try:
    from kdc_server.database import get_db_conn
except ImportError:
    print("Error: Could not import 'get_db_conn' from 'kdc_server.database'.")
    print("Ensure 'kdc_server/database.py' exists and the path is correct.")
    sys.exit(1)

# --- Flask App Initialization ---
app = Flask(__name__)


@app.route('/create-user', methods=['POST'])
def create_user():
    """
    API endpoint to create a new user principal in the KDC database.
    This should be called by your signup logic (e.g., from the CA server) 
    after a certificate has been successfully issued.
    
    Expects JSON payload:
    {
        "username": "newuser",
        "cert_subject": "CN=newuser,O=MyKerberosProject"
    }
    """
    data = request.get_json(silent=True) or {}
    username = data.get('username')
    cert_subject = data.get('cert_subject')

    if not username or not cert_subject:
        return jsonify({"error": "username and cert_subject are required"}), 400

    principal_name = f"{username}@{YOUR_REALM}"
    
    conn = None
    try:
        conn = get_db_conn()
        cursor = conn.cursor()
        
        # Insert the new user, linking them to their certificate subject
        # for 'pkinit' (certificate-based) authentication.
        cursor.execute(
            """
            INSERT INTO principals (principal_name, auth_type, cert_subject, secret_key_hash)
            VALUES (?, 'pkinit', ?, NULL)
            """,
            (principal_name, cert_subject)
        )
        conn.commit()
        
        print(f"Successfully provisioned principal: {principal_name}")
        return jsonify({
            "message": "User principal created successfully",
            "principal_name": principal_name,
            "auth_type": "pkinit",
            "cert_subject": cert_subject
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

if __name__ == '__main__':
    print("--- Starting Provisioning API Server ---")
    
    # Note: The 'primary-kdc' container must run first
    # to call 'init_kdc_db()' and create the database file.
    
    # Run the Flask server, making it accessible within the Docker network
    app.run(host='0.0.0.0', port=5001)

