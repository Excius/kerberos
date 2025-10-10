# Shared utility functions (e.g., encryption helpers)

from cryptography.fernet import Fernet

# fernet uses AES-CBC (with a randomly generated 128-bit key). It also uses HMAC with SHA256 to ensure the integrity of the encrypted data.(not tempered)

def encrypt_data(key: bytes, data: bytes) -> bytes:
    cipher = Fernet(key)
    return cipher.encrypt(data)

def decrypt_data(key: bytes, token: bytes) -> bytes:
    cipher = Fernet(key)
    return cipher.decrypt(token)