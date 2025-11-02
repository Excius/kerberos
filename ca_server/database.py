import os
import sqlite3

# --- Configuration ---
CA_DATA_DIR = "/app/data"
DB_PATH = os.path.join(CA_DATA_DIR, "ca.db")

# Ensure the data directory exists
os.makedirs(CA_DATA_DIR, exist_ok=True)

def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    """Initializes the CA's private database."""
    with get_db() as conn:
        # This table tracks certificates the CA has issued
        # This is the CA's "source of truth" for what certs are valid
        conn.execute("""
        CREATE TABLE IF NOT EXISTS certificates (
            serial_number INTEGER PRIMARY KEY,
            subject_name TEXT NOT NULL,
            principal_name TEXT NOT NULL,
            status TEXT NOT NULL,  -- 'trusted', 'revoked'
            issued_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            expires_at TIMESTAMP NOT NULL,
            fingerprint TEXT NOT NULL UNIQUE
        );
        """)
        
        # This table tracks pending requests for new devices
        conn.execute("""
        CREATE TABLE IF NOT EXISTS pending_requests (
            request_id TEXT PRIMARY KEY,
            principal_name TEXT NOT NULL,
            new_csr_pem TEXT NOT NULL,
            new_cert_subject TEXT NOT NULL,
            status TEXT NOT NULL DEFAULT 'pending', -- 'pending', 'approved'
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        );
        """)
        conn.commit()
    print("CA Database initialized (with pending_requests table).")
