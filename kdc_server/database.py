import os
import sqlite3
from config.config import REALM, SERVICE_SECRET_KEY_B64, TGS_SECRET_KEY_B64

# Define the path to the database, which will live in the persistent volume
DB_DIR = "/app/db/primary"
DB_PATH = os.path.join(DB_DIR, "kdc.db")

# Ensure the DB directory exists
os.makedirs(DB_DIR, exist_ok=True)

def get_db_conn(path=DB_PATH):
    """Establishes a connection to the KDC SQLite database."""
    conn = sqlite3.connect(path)
    conn.row_factory = sqlite3.Row
    # Enable foreign key support in SQLite
    conn.execute("PRAGMA foreign_keys = ON;")
    return conn

def init_kdc_db():
    """Initializes the new KDC database schema with users and devices."""
    try:
        conn = get_db_conn()
        cursor = conn.cursor()
        
        # --- NEW SCHEMA ---
        # 1. 'users' table holds the master account
        cursor.execute("""
        CREATE TABLE IF NOT EXISTS users (
            user_id INTEGER PRIMARY KEY AUTOINCREMENT,
            principal_name TEXT NOT NULL UNIQUE
        );
        """)
        
        # 2. 'devices' table holds all trusted certificates for each user
        cursor.execute("""
        CREATE TABLE IF NOT EXISTS devices (
            device_id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            cert_fingerprint TEXT NOT NULL UNIQUE,
            cert_subject TEXT NOT NULL,
            status TEXT NOT NULL DEFAULT 'trusted',  -- 'trusted' or 'pending'
            FOREIGN KEY (user_id) REFERENCES users (user_id) ON DELETE CASCADE
        );
        """)
        
        # 3. 'service_keys' table for TGS and other services
        cursor.execute("""
        CREATE TABLE IF NOT EXISTS service_keys (
            principal_name TEXT PRIMARY KEY NOT NULL,
            secret_key_b64 TEXT NOT NULL
        );
        """)
        
        # Insert the TGS principal
        cursor.execute("""
        INSERT OR IGNORE INTO service_keys (principal_name, secret_key_b64)
        VALUES (?, ?)
        """, (f"tgs@{REALM}", TGS_SECRET_KEY_B64,))
        
        # Insert the Service Server principal
        cursor.execute("""
        INSERT OR IGNORE INTO service_keys (principal_name, secret_key_b64)
        VALUES (?, ?)
        """, (f"host/service.server@{REALM}", SERVICE_SECRET_KEY_B64,))
        
        conn.commit()
        print("KDC multi-device database initialized successfully.")
    except Exception as e:
        print(f"Error initializing KDC database: {e}")
    finally:
        if 'conn' in locals() and conn:
            conn.close()
