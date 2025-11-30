from crypto_manager import CryptoManager
from access_control import AccessControlSystem
from audit_system import AuditSystem
from patient_records import PatientRecordsManager

def test_patient_record_creation():
    print("Testing patient record creation...")
    
    crypto = CryptoManager()
    access = AccessControlSystem(crypto)
    audit = AuditSystem(crypto)
    
    # Initialize audit keys
    audit_priv, audit_pub = crypto.generate_rsa_keypair()
    crypto.audit_private_key = audit_priv
    crypto.audit_public_key = audit_pub
    
    patient_mgr = PatientRecordsManager(crypto, access, audit)
    
    # Create user and authenticate
    priv, pub = crypto.generate_rsa_keypair()
    user_id = access.register_user("test_doc", "password123", "physician", pub)
    session, msg = access.authenticate_user("test_doc", "password123")
    
    print(f"Authentication: {msg}")
    
    # Create patient record
    patient_data = {
        'name': 'Test Patient',
        'dob': '1990-01-01',
        'condition': 'Test condition'
    }
    
    patient_id, create_msg = patient_mgr.create_patient_record(session, patient_data)
    print(f"Patient record creation: {create_msg}")
    print(f"Patient ID: {patient_id}")
    
    # Access patient record
    record, access_msg = patient_mgr.access_patient_record(session, patient_id, "Test")
    print(f"Record access: {access_msg}")
    if record:
        print(f"Patient name: {record.get('name')}")
    
    return True

if __name__ == "__main__":
    test_patient_record_creation()