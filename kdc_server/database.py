import os
import sqlite3

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
        secret_key_hash TEXT
    );
    """)
    
    # We can also pre-load the TGS and other service principals here
    # (This is a simplified example)
    # cursor.execute("""
    # INSERT OR IGNORE INTO principals (principal_name, auth_type, secret_key_hash)
    # VALUES ('tgs@YOUR_REALM', 'pre-shared-key', 'super-secret-tgs-key-hash');
    # """)
    
    conn.commit()
    conn.close()
    print("KDC database initialized.")
