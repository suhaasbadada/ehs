import hashlib
import hmac
import json
import time
import os
import base64
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
import secrets

class CryptoManager:
    def __init__(self):
        self.backend = default_backend()
        # Generate a master key for key encryption
        self.master_key = os.urandom(32)  # 32 bytes for AES-256
        # Initialize audit keys (will be set by the system)
        self.audit_private_key = None
        self.audit_public_key = None
    
    def generate_rsa_keypair(self):
        """Generate RSA key pair for digital signatures and encryption"""
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
            backend=self.backend
        )
        public_key = private_key.public_key()
        return private_key, public_key
    
    def generate_aes_key(self):
        """Generate AES symmetric key for data encryption"""
        return os.urandom(32)  # 32 bytes for AES-256
    
    def encrypt_data(self, data, key):
        """Encrypt data using AES-GCM"""
        if isinstance(data, dict):
            data = json.dumps(data, ensure_ascii=False).encode('utf-8')
        elif isinstance(data, str):
            data = data.encode('utf-8')
        
        # Ensure key is exactly 32 bytes
        if len(key) != 32:
            raise ValueError(f"Invalid key size ({len(key)}) for AES. Must be 32 bytes.")
        
        iv = os.urandom(12)  # 96-bit IV for GCM
        cipher = Cipher(algorithms.AES(key), modes.GCM(iv), backend=self.backend)
        encryptor = cipher.encryptor()
        ciphertext = encryptor.update(data) + encryptor.finalize()
        
        # Return IV + tag + ciphertext
        return base64.b64encode(iv + encryptor.tag + ciphertext).decode('utf-8')
    
    def decrypt_data(self, encrypted_data, key):
        """Decrypt data using AES-GCM"""
        # Ensure key is exactly 32 bytes
        if len(key) != 32:
            raise ValueError(f"Invalid key size ({len(key)}) for AES. Must be 32 bytes.")
        
        encrypted_bytes = base64.b64decode(encrypted_data)
        iv = encrypted_bytes[:12]  # First 12 bytes are IV
        tag = encrypted_bytes[12:28]  # Next 16 bytes are tag
        ciphertext = encrypted_bytes[28:]  # Rest is ciphertext
        
        cipher = Cipher(algorithms.AES(key), modes.GCM(iv, tag), backend=self.backend)
        decryptor = cipher.decryptor()
        decrypted = decryptor.update(ciphertext) + decryptor.finalize()
        
        try:
            # Try to parse as JSON first
            return json.loads(decrypted.decode('utf-8'))
        except json.JSONDecodeError:
            # Return as string if not JSON
            return decrypted.decode('utf-8')
    
    def create_signature(self, private_key, data):
        """Create digital signature"""
        if isinstance(data, dict):
            data = json.dumps(data, sort_keys=True, ensure_ascii=False)
        elif not isinstance(data, str):
            data = str(data)
            
        signature = private_key.sign(
            data.encode('utf-8'),
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        return base64.b64encode(signature).decode('utf-8')
    
    def verify_signature(self, public_key, data, signature):
        """Verify digital signature"""
        if isinstance(data, dict):
            data = json.dumps(data, sort_keys=True, ensure_ascii=False)
        elif not isinstance(data, str):
            data = str(data)
            
        try:
            public_key.verify(
                base64.b64decode(signature),
                data.encode('utf-8'),
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH
                ),
                hashes.SHA256()
            )
            return True
        except Exception as e:
            print(f"Signature verification failed: {e}")
            return False
    
    def hash_sensitive_data(self, data):
        """Hash sensitive data - return hex string"""
        if isinstance(data, dict):
            data = json.dumps(data, sort_keys=True, ensure_ascii=False)
        data_bytes = data.encode('utf-8') if isinstance(data, str) else data
        
        # Use SHA256 for hashing
        return hashlib.sha256(data_bytes).hexdigest()
    
    def generate_secure_token(self, length=32):
        """Generate cryptographically secure token"""
        return secrets.token_urlsafe(length)
    
    def encrypt_key_for_storage(self, key):
        """Encrypt a key using the master key for storage"""
        # For key encryption, we need to handle raw bytes differently
        iv = os.urandom(12)
        cipher = Cipher(algorithms.AES(self.master_key), modes.GCM(iv), backend=self.backend)
        encryptor = cipher.encryptor()
        ciphertext = encryptor.update(key) + encryptor.finalize()
        return base64.b64encode(iv + encryptor.tag + ciphertext).decode('utf-8')
    
    def decrypt_key_from_storage(self, encrypted_key):
        """Decrypt a key that was stored encrypted"""
        encrypted_bytes = base64.b64decode(encrypted_key)
        iv = encrypted_bytes[:12]
        tag = encrypted_bytes[12:28]
        ciphertext = encrypted_bytes[28:]
        
        cipher = Cipher(algorithms.AES(self.master_key), modes.GCM(iv, tag), backend=self.backend)
        decryptor = cipher.decryptor()
        return decryptor.update(ciphertext) + decryptor.finalize()
