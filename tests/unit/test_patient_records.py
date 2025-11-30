import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

from src.core.crypto_manager import CryptoManager
from src.auth.access_control import AccessControlSystem
from src.audit.audit_system import AuditSystem
from src.data.patient_records import PatientRecordsManager

def test_patient_records():
    """Test patient record management"""
    print("Testing patient records...")
    
    crypto = CryptoManager()
    auth = AccessControlSystem(crypto)
    audit = AuditSystem(crypto)
    
    # Initialize audit keys
    audit_priv, audit_pub = crypto.generate_rsa_keypair()
    crypto.audit_private_key = audit_priv
    crypto.audit_public_key = audit_pub
    
    patient_mgr = PatientRecordsManager(crypto, auth, audit)
    
    # Register and authenticate doctor
    priv, pub = crypto.generate_rsa_keypair()
    auth.register_user("doctor", "Doctor123!", "physician", pub)
    session, _ = auth.authenticate_user("doctor", "Doctor123!")
    
    # Create patient record
    patient_data = {'name': 'Test Patient', 'dob': '1990-01-01'}
    patient_id, msg = patient_mgr.create_patient_record(session, patient_data)
    assert patient_id is not None, "Patient record creation failed"
    print(f"✅ Patient record created: {patient_id}")
    
    # Access patient record
    record, msg = patient_mgr.access_patient_record(session, patient_id, "Test")
    assert record is not None, "Patient record access failed"
    print("✅ Patient record access passed")

if __name__ == "__main__":
    test_patient_records()
    print("All patient record tests passed!")
