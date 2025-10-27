# Client script to request tickets and access services

import requests
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa

# --- This code would run on the client's machine ---

# 1. Generate new private key
key = rsa.generate_private_key(
    public_exponent=65537,
    key_size=2048,
)

# 2. Save the private key (THEY KEEP THIS SECRET)
with open("my_private_key.pem", "wb") as f:
    f.write(key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    ))
print("Saved my_private_key.pem")

# 3. Create a Certificate Signing Request (CSR)
subject_name = "testuser" # This would be the user's name
csr = x509.CertificateSigningRequestBuilder().subject_name(
    x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, "IN"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "MyKerberosProject"),
        x509.NameAttribute(NameOID.COMMON_NAME, subject_name),
    ])
).sign(key, hashes.SHA256()) # Sign the CSR with our new private key

csr_pem = csr.public_bytes(serialization.Encoding.PEM)

# 4. Submit the CSR to the CA Server API
try:
    # URL for the CA server (replace with actual URL if not in docker-compose)
    ca_url = "http://localhost:5000"
    
    response = requests.post(
        f"{ca_url}/submit-csr",
        data=csr_pem,
        headers={'Content-Type': 'application/pem-certificate-request'},
        verify=False # In production, you'd get the CA cert first and verify
    )

    if response.status_code == 201:
        # 5. Receive the signed certificate
        with open("my_certificate.pem", "wb") as f:
            f.write(response.content)
        print("Success! Received and saved my_certificate.pem")
    else:
        print(f"Error: {response.status_code}")
        print(response.text)

except requests.exceptions.ConnectionError as e:
    print(f"Connection Error: Could not connect to CA server at {ca_url}.")
    print("Is the CA server running and the port mapping correct?")