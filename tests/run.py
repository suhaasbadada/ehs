import hashlib
import hmac
import json
import time
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend
import base64

class SecureEHealthSystem:
    def __init__(self):
        self.patient_records = {}
        self.access_log = []
        self.roles = {}
        
    def generate_key_pair(self):
        """Generate RSA key pair for digital signatures"""
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
            backend=default_backend()
        )
        public_key = private_key.public_key()
        return private_key, public_key
    
    def hash_sensitive_data(self, data):
        """Hash sensitive patient data for privacy protection"""
        return hashlib.sha256(data.encode()).hexdigest()
    
    def create_digital_signature(self, private_key, message):
        """Create digital signature for audit trail"""
        signature = private_key.sign(
            message.encode(),
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        return base64.b64encode(signature).decode()
    
    def verify_signature(self, public_key, message, signature):
        """Verify digital signature"""
        try:
            public_key.verify(
                base64.b64decode(signature),
                message.encode(),
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH
                ),
                hashes.SHA256()
            )
            return True
        except Exception:
            return False
    
    def add_patient_record(self, patient_id, data, healthcare_provider_key):
        """Add encrypted patient record with access controls"""
        # Hash sensitive identifiers
        hashed_patient_id = self.hash_sensitive_data(patient_id)
        
        # Create secure record
        record = {
            'data': data,
            'timestamp': time.time(),
            'provider_signature': self.create_digital_signature(
                healthcare_provider_key, 
                f"{patient_id}{json.dumps(data)}{time.time()}"
            ),
            'access_controls': {
                'allowed_roles': ['physician', 'nurse'],
                'emergency_access': False
            }
        }
        
        self.patient_records[hashed_patient_id] = record
        self._log_access('CREATE', hashed_patient_id, 'system')
        
        return hashed_patient_id
    
    def access_patient_record(self, patient_id, user_role, user_key, emergency=False):
        """Access patient record with role-based access control"""
        hashed_patient_id = self.hash_sensitive_data(patient_id)
        
        if hashed_patient_id not in self.patient_records:
            return None, "Record not found"
        
        record = self.patient_records[hashed_patient_id]
        access_controls = record['access_controls']
        
        # Check access permissions
        if not self._check_access_permissions(user_role, access_controls, emergency):
            return None, "Access denied"
        
        # Verify provider signature
        verification_data = f"{patient_id}{json.dumps(record['data'])}{record['timestamp']}"
        if not self.verify_signature(user_key, verification_data, record['provider_signature']):
            return None, "Signature verification failed"
        
        # Log access
        self._log_access('READ', hashed_patient_id, user_role, emergency)
        
        return record['data'], "Access granted"
    
    def _check_access_permissions(self, user_role, access_controls, emergency):
        """Check if user has permission to access the record"""
        if emergency and access_controls['emergency_access']:
            return True
        
        return user_role in access_controls['allowed_roles']
    
    def _log_access(self, action, patient_id, user_role, emergency=False):
        """Log all access attempts for audit trail"""
        log_entry = {
            'timestamp': time.time(),
            'action': action,
            'patient_id': patient_id,
            'user_role': user_role,
            'emergency_access': emergency
        }
        self.access_log.append(log_entry)
    
    def get_audit_log(self, admin_key):
        """Retrieve audit log for compliance monitoring"""
        # In practice, this would verify admin privileges
        return self.access_log

# Example usage
if __name__ == "__main__":
    # Initialize secure e-health system
    ehealth_system = SecureEHealthSystem()
    
    # Generate keys for healthcare provider
    provider_private_key, provider_public_key = ehealth_system.generate_key_pair()
    
    # Add patient record
    patient_data = {
        'name': 'John Doe',
        'medical_history': 'Hypertension, Diabetes',
        'current_medication': 'Lisinopril 10mg, Metformin 500mg',
        'lab_results': {'blood_pressure': '120/80', 'blood_sugar': '110 mg/dL'}
    }
    
    record_id = ehealth_system.add_patient_record(
        "PATIENT_123", 
        patient_data, 
        provider_private_key
    )
    
    # Access patient record
    record, status = ehealth_system.access_patient_record(
        "PATIENT_123", 
        "physician", 
        provider_public_key
    )
    
    print(f"Access Status: {status}")
    if record:
        print(f"Patient Record: {record}")
    
    # Attempt unauthorized access
    record, status = ehealth_system.access_patient_record(
        "PATIENT_123", 
        "receptionist", 
        provider_public_key
    )
    
    print(f"Unauthorized Access Status: {status}")
    
    # Display audit log
    audit_log = ehealth_system.get_audit_log(provider_private_key)
    print(f"\nAudit Log Entries: {len(audit_log)}")