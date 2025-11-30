import sys
import os
import time
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

from src.core.crypto_manager import CryptoManager
from src.auth.access_control import AccessControlSystem
from src.audit.audit_system import AuditSystem
from src.data.patient_records import PatientRecordsManager
from src.data.medical_devices import MedicalDeviceManager

def test_system_integration():
    """Test complete system integration"""
    print("Testing system integration...")
    
    # Initialize all components
    crypto = CryptoManager()
    auth = AccessControlSystem(crypto)
    audit = AuditSystem(crypto)
    patient_mgr = PatientRecordsManager(crypto, auth, audit)
    device_mgr = MedicalDeviceManager(crypto, audit)
    
    # Set audit keys
    audit_priv, audit_pub = crypto.generate_rsa_keypair()
    crypto.audit_private_key = audit_priv
    crypto.audit_public_key = audit_pub
    
    # Register users
    doc_priv, doc_pub = crypto.generate_rsa_keypair()
    auth.register_user("dr_test", "DoctorPass123!", "physician", doc_pub)
    
    # Authenticate
    session, _ = auth.authenticate_user("dr_test", "DoctorPass123!")
    print("✅ User authentication successful")
    
    # Create patient record
    patient_data = {'name': 'Integration Test Patient', 'dob': '1985-06-15'}
    patient_id, _ = patient_mgr.create_patient_record(session, patient_data)
    print(f"✅ Patient record created: {patient_id[:16]}...")
    
    # Access patient record
    record, _ = patient_mgr.access_patient_record(session, patient_id, "Test")
    print("✅ Patient record accessed")
    
    # Check audit logs
    report = audit.generate_compliance_report(time.time() - 3600, time.time())
    print(f"✅ Audit report generated: {report['total_events']} events")

if __name__ == "__main__":
    test_system_integration()
    print("System integration test passed!")
