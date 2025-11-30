import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

from src.core.crypto_manager import CryptoManager
from src.auth.access_control import AccessControlSystem

def test_auth():
    """Test authentication"""
    print("Testing authentication...")
    
    crypto = CryptoManager()
    auth = AccessControlSystem(crypto)
    
    # Register user
    priv, pub = crypto.generate_rsa_keypair()
    user_id = auth.register_user("test_user", "TestPass123!", "physician", pub)
    print(f"✅ User registered: {user_id}")
    
    # Test authentication
    session, msg = auth.authenticate_user("test_user", "TestPass123!")
    assert session is not None, "Authentication failed"
    print("✅ Authentication passed")
    
    # Test permission checking
    has_perm, msg = auth.check_permission(session, "read_patient_data")
    assert has_perm, "Permission check failed"
    print("✅ Permission check passed")

if __name__ == "__main__":
    test_auth()
    print("All auth tests passed!")
