import os
import sqlite3
from config.config import REALM, SERVICE_SECRET_KEY_B64, TGS_SECRET_KEY_B64

# Define the path to the database, which will live in the persistent volume
DB_DIR = "/app/db"
DB_PATH = os.path.join(DB_DIR, "kdc.db")

# Ensure the DB directory exists
os.makedirs(DB_DIR, exist_ok=True)

def get_db_conn():
    """Establishes a connection to the KDC SQLite database."""
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

def init_kdc_db():
    """
    Initializes the KDC database tables if they don't exist.
    This should be called by the primary-kdc on startup.
    """
    conn = get_db_conn()
    cursor = conn.cursor()
    
    # This table maps Kerberos principals to their authentication info
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS principals (
        principal_name TEXT PRIMARY KEY NOT NULL,
        auth_type TEXT NOT NULL,
        cert_subject TEXT UNIQUE,
        cert_fingerprint TEXT UNIQUE,
        secret_key_b64 TEXT
    );
    """)
    
    # We can also pre-load the TGS and other service principals here
    # (This is a simplified example)
    cursor.execute(f"""
    INSERT OR IGNORE INTO principals (principal_name, auth_type, secret_key_b64)
    VALUES ('tgs@{REALM}', 'pre-shared-key', ?)
    """, (TGS_SECRET_KEY_B64,))
    
    # Insert the Service Server principal with its base64-encoded secret key
    cursor.execute(f"""
    INSERT OR IGNORE INTO principals (principal_name, auth_type, secret_key_b64)
    VALUES ('host/service.server@{REALM}', 'pre-shared-key', ?)
    """, (SERVICE_SECRET_KEY_B64,))

    conn.commit()
    conn.close()
    print("KDC database initialized.")
