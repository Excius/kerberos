import argparse
import time
from kdc_server.database import init_kdc_db

def start_kdc(role):
    """Starts the KDC in the specified role."""
    print(f"--- Starting KDC Server (Role: {role}) ---")
    
    if role == 'primary':
        # The primary KDC is responsible for initializing the database
        print("Role is PRIMARY. Initializing database...")
        init_kdc_db()
        # TODO: Start the main KDC (AS/TGS) listener loop
        
    elif role == 'replica':
        # The replica KDC just loads the DB (which is synced by a script)
        print("Role is REPLICA.")
        # TODO: Implement database sync check
        # TODO: Start the main KDC (AS/TGS) listener loop (read-only)
        
    else:
        print(f"Error: Unknown role '{role}'")
        return

    print("KDC service is running.")
    # For now, we'll just idle to keep the container alive
    try:
        while True:
            time.sleep(3600)
    except KeyboardInterrupt:
        print("KDC service shutting down.")

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
    
    start_kdc(args.role)
