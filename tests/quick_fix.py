from src.core.crypto_manager import CryptoManager
from src.auth.access_control import AccessControlSystem

# Test basic functionality
print("Testing basic crypto and auth...")

crypto = CryptoManager()
auth = AccessControlSystem(crypto)

# Generate keys
priv, pub = crypto.generate_rsa_keypair()

# Register user
user_id = auth.register_user("test", "test123", "physician", pub)
print(f"User registered: {user_id}")

# Authenticate
session, msg = auth.authenticate_user("test", "test123")
print(f"Auth result: {msg}")
print(f"Session valid: {session is not None}")

# Test encryption
test_data = {"message": "Hello World"}
key = crypto.generate_aes_key()
encrypted = crypto.encrypt_data(test_data, key)
decrypted = crypto.decrypt_data(encrypted, key)
print(f"Encryption test: {test_data == decrypted}")

print("Basic tests completed!")