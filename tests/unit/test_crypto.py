import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

from src.core.crypto_manager import CryptoManager

def test_crypto():
    """Test cryptographic functions"""
    print("Testing cryptographic functions...")
    
    crypto = CryptoManager()
    
    # Test AES encryption
    data = {"message": "Hello"}
    key = crypto.generate_aes_key()
    encrypted = crypto.encrypt_data(data, key)
    decrypted = crypto.decrypt_data(encrypted, key)
    
    assert data == decrypted, "Encryption/decryption failed"
    print("✅ AES encryption/decryption passed")
    
    # Test RSA signatures
    priv, pub = crypto.generate_rsa_keypair()
    signature = crypto.create_signature(priv, data)
    verified = crypto.verify_signature(pub, data, signature)
    
    assert verified, "Signature verification failed"
    print("✅ RSA signature verification passed")

if __name__ == "__main__":
    test_crypto()
    print("All crypto tests passed!")
