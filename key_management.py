# key_management.py
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes
import os
from config import Config

def load_or_generate_keys():
    private_key_path = Config.RSA_PRIVATE_KEY_PATH
    public_key_path = Config.RSA_PUBLIC_KEY_PATH

    if not os.path.exists(private_key_path) or not os.path.exists(public_key_path):
        # Generate a new key pair
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
        )
        public_key = private_key.public_key()

        # Save private key
        with open(private_key_path, 'wb') as f:
            f.write(
                private_key.private_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PrivateFormat.TraditionalOpenSSL,
                    encryption_algorithm=serialization.NoEncryption()
                )
            )
        
        # Save public key
        with open(public_key_path, 'wb') as f:
            f.write(
                public_key.public_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PublicFormat.SubjectPublicKeyInfo
                )
            )
    else:
        # Keys exist
        pass

def get_private_key():
    with open(Config.RSA_PRIVATE_KEY_PATH, 'rb') as f:
        private_key = serialization.load_pem_private_key(
            f.read(),
            password=None,
        )
    return private_key

def get_public_key():
    with open(Config.RSA_PUBLIC_KEY_PATH, 'rb') as f:
        public_key = serialization.load_pem_public_key(f.read())
    return public_key

def get_public_key_pem():
    with open(Config.RSA_PUBLIC_KEY_PATH, 'rb') as f:
        return f.read()

def decrypt_session_key(encrypted_key):
    private_key = get_private_key()
    session_key = private_key.decrypt(
        encrypted_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return session_key

def encrypt_with_public_key(data):
    public_key = get_public_key()  # Implement a get_public_key() that returns a loaded public key object
    encrypted = public_key.encrypt(
        data,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return encrypted

def decrypt_with_private_key(encrypted_data):
    private_key = get_private_key()
    decrypted = private_key.decrypt(
        encrypted_data,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return decrypted
