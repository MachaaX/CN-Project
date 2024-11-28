# utils.py
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
import os

# Fetch encryption key from environment variable (must be a valid 32-byte hex string)
encryption_hex_key = os.environ.get('ENCRYPTION_KEY')

if encryption_hex_key is None:
    raise Exception("Encryption key not found in environment variables.")

# Convert the hex key to bytes
try:
    encryption_key = bytes.fromhex(encryption_hex_key)
    if len(encryption_key) not in [16, 24, 32]:
        raise ValueError("Encryption key must be 16, 24, or 32 bytes long.")
except ValueError as e:
    raise Exception(f"Invalid encryption key: {e}")

def encrypt_data(plaintext):
    """Encrypt text or binary data."""
    # If plaintext is binary data (like file), no need to encode, just ensure it's in bytes
    if isinstance(plaintext, str):
        plaintext = plaintext.encode('utf-8')
    
    iv = os.urandom(16)  # Initialization vector
    cipher = Cipher(algorithms.AES(encryption_key), modes.CBC(iv))
    encryptor = cipher.encryptor()

    # Pad plaintext to match block size for AES (block size is 16 bytes)
    padder = padding.PKCS7(128).padder()
    padded_data = padder.update(plaintext) + padder.finalize()

    # Encrypt the padded data
    ciphertext = encryptor.update(padded_data) + encryptor.finalize()

    # Return IV + ciphertext as a single binary string
    return iv + ciphertext


def decrypt_data(ciphertext):
    """Decrypt text or binary data."""
    iv = ciphertext[:16]  # Extract the IV
    actual_ciphertext = ciphertext[16:]  # Extract the encrypted data
    cipher = Cipher(algorithms.AES(encryption_key), modes.CBC(iv))
    decryptor = cipher.decryptor()

    # Decrypt and unpad the data
    padded_plaintext = decryptor.update(actual_ciphertext) + decryptor.finalize()
    unpadder = padding.PKCS7(128).unpadder()
    plaintext = unpadder.update(padded_plaintext) + unpadder.finalize()

    # Return the decrypted plaintext as a string or binary data
    try:
        return plaintext.decode('utf-8')  # Try to decode as UTF-8 if it's a string
    except UnicodeDecodeError:
        return plaintext  # If it's not a string, return as bytes (e.g., file data)
