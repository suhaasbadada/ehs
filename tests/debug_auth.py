from crypto_manager import CryptoManager
from access_control import AccessControlSystem

def debug_authentication():
    """Simple script to debug authentication issues"""
    print("🔧 DEBUGGING AUTHENTICATION")
    
    crypto = CryptoManager()
    auth = AccessControlSystem(crypto)
    
    # Generate keys
    priv_key, pub_key = crypto.generate_rsa_keypair()
    
    # Register user
    print("\n1. Registering user...")
    user_id = auth.register_user("admin", "Admin123!", "admin", pub_key)
    print(f"User ID: {user_id}")
    
    # List users (debug)
    print(f"\n2. Registered users: {list(auth.users.keys())}")
    
    # Test authentication
    print("\n3. Testing authentication...")
    session, message = auth.authenticate_user("admin", "Admin123!")
    print(f"Result: {message}")
    print(f"Session: {session}")
    
    if session:
        print("✅ Authentication SUCCESSFUL!")
    else:
        print("❌ Authentication FAILED!")
        
        # Debug info
        user = auth.users.get("admin")
        if user:
            print(f"Stored hash: {user['password_hash'].hex()[:32]}...")
            print(f"Salt: {user['salt'].hex()[:32]}...")

if __name__ == "__main__":
    debug_authentication()