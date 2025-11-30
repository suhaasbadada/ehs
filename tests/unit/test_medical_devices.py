import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

from src.core.crypto_manager import CryptoManager
from src.audit.audit_system import AuditSystem
from src.data.medical_devices import MedicalDeviceManager

def test_medical_devices():
    """Test medical device integration"""
    print("Testing medical devices...")
    
    crypto = CryptoManager()
    audit = AuditSystem(crypto)
    device_mgr = MedicalDeviceManager(crypto, audit)
    
    # Register device
    dev_priv, dev_pub = crypto.generate_rsa_keypair()
    cert = device_mgr.register_device("HR_001", "Heart Rate Monitor", dev_pub, "Ward A")
    assert cert is not None, "Device registration failed"
    print(f"✅ Device registered: {cert['device_id']}")

if __name__ == "__main__":
    test_medical_devices()
    print("All medical device tests passed!")
