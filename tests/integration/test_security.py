import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

from src.core.crypto_manager import CryptoManager
from src.auth.access_control import AccessControlSystem

def test_security():
    """Test security features"""
    print("Testing security features...")
    
    crypto = CryptoManager()
    
    # Test password security
    auth = AccessControlSystem(crypto)
    priv, pub = crypto.generate_rsa_keypair()
    auth.register_user("secure_user", "SecurePass123!", "physician", pub)
    
    # Verify failed login is rejected
    session, msg = auth.authenticate_user("secure_user", "WrongPassword")
    assert session is None, "Wrong password was accepted"
    print("✅ Password security verified")
    
    # Test encryption security
    sensitive_data = {"ssn": "123-45-6789", "insurance": "ABC123"}
    key = crypto.generate_aes_key()
    encrypted = crypto.encrypt_data(sensitive_data, key)
    
    # Verify encrypted data is not plain text
    assert str(sensitive_data) not in encrypted, "Data not encrypted properly"
    print("✅ Encryption security verified")

if __name__ == "__main__":
    test_security()
    print("Security tests passed!")
