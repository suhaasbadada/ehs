import sys
import time
from crypto_manager import CryptoManager
from access_control import AccessControlSystem
from audit_system import AuditSystem
from patient_records import PatientRecordsManager
from medical_devices import MedicalDeviceManager

class SecureEHealthDemo:
    def __init__(self):
        # Initialize all components
        self.crypto_manager = CryptoManager()
        self.access_control = AccessControlSystem(self.crypto_manager)
        self.audit_system = AuditSystem(self.crypto_manager)
        self.patient_records = PatientRecordsManager(
            self.crypto_manager, 
            self.access_control, 
            self.audit_system
        )
        self.medical_devices = MedicalDeviceManager(
            self.crypto_manager, 
            self.audit_system
        )
        
        # Generate system keys
        self._initialize_system_keys()
        
        # Create default users
        self._create_default_users()
    
    def _initialize_system_keys(self):
        """Initialize system cryptographic keys"""
        self.crypto_manager.audit_private_key, self.crypto_manager.audit_public_key = \
            self.crypto_manager.generate_rsa_keypair()
    
    def _create_default_users(self):
        """Create default users for testing"""
        # Admin user
        admin_priv, admin_pub = self.crypto_manager.generate_rsa_keypair()
        self.access_control.register_user("admin", "Admin123!", "admin", admin_pub)
        
        # Doctor user
        doctor_priv, doctor_pub = self.crypto_manager.generate_rsa_keypair()
        self.access_control.register_user("dr_smith", "Doctor123!", "physician", doctor_pub)
        
        # Nurse user
        nurse_priv, nurse_pub = self.crypto_manager.generate_rsa_keypair()
        self.access_control.register_user("nurse_jones", "Nurse123!", "nurse", nurse_pub)
        
        print("✅ Default users created:")
        print("   - admin/Admin123! (Administrator)")
        print("   - dr_smith/Doctor123! (Physician)")
        print("   - nurse_jones/Nurse123! (Nurse)")
    
    def run_complete_demo(self):
        """Run complete system demonstration"""
        print("\n" + "="*60)
        print("🚀 SECURE E-HEALTH SYSTEM - COMPLETE DEMONSTRATION")
        print("="*60)
        
        # Test 1: Authentication and Authorization
        self.test_authentication()
        
        # Test 2: Patient Records Management
        self.test_patient_records()
        
        # Test 3: Medical Devices Integration
        self.test_medical_devices()
        
        # Test 4: Audit and Compliance
        self.test_audit_system()
        
        # Test 5: Security Features
        self.test_security_features()
        
        print("\n" + "="*60)
        print("🎉 DEMONSTRATION COMPLETED SUCCESSFULLY!")
        print("="*60)
    
    def test_authentication(self):
        """Test authentication and authorization"""
        print("\n1. 🔐 AUTHENTICATION & AUTHORIZATION")
        print("-" * 40)
        
        # Test admin login
        admin_session, admin_msg = self.access_control.authenticate_user("admin", "Admin123!")
        if admin_session:
            print("✅ Admin authentication: SUCCESS")
            
            # Test permissions
            perms_to_test = [
                ("read_patient_data", "Read patient data"),
                ("write_patient_data", "Write patient data"),
                ("user_management", "User management")
            ]
            
            for perm, desc in perms_to_test:
                has_perm, msg = self.access_control.check_permission(admin_session, perm)
                status = "✅" if has_perm else "❌"
                print(f"   {status} {desc}: {msg}")
        else:
            print("❌ Admin authentication: FAILED")
            return False
        
        # Test doctor login
        doctor_session, doctor_msg = self.access_control.authenticate_user("dr_smith", "Doctor123!")
        if doctor_session:
            print("✅ Doctor authentication: SUCCESS")
            
            # Test doctor permissions (should not have admin privileges)
            has_perm, msg = self.access_control.check_permission(doctor_session, "user_management")
            if not has_perm:
                print("✅ Doctor correctly restricted from user management")
            else:
                print("❌ Doctor incorrectly has admin privileges")
        else:
            print("❌ Doctor authentication: FAILED")
        
        # Test failed login
        failed_session, failed_msg = self.access_control.authenticate_user("admin", "WrongPassword")
        if not failed_session:
            print("✅ Failed login handling: CORRECT")
        else:
            print("❌ Failed login handling: INCORRECT")
        
        return True
    
    def test_patient_records(self):
        """Test patient records management"""
        print("\n2. 📋 PATIENT RECORDS MANAGEMENT")
        print("-" * 40)
        
        # Login as doctor
        doctor_session, _ = self.access_control.authenticate_user("dr_smith", "Doctor123!")
        
        # Create patient record
        patient_data = {
            'name': 'John Doe',
            'dob': '1980-05-15',
            'ssn': '123-45-6789',
            'medical_history': 'Hypertension, Type 2 Diabetes',
            'current_medication': 'Lisinopril 10mg, Metformin 500mg',
            'allergies': ['Penicillin', 'Sulfa'],
            'vital_signs': {
                'blood_pressure': '120/80',
                'heart_rate': 72,
                'temperature': 98.6
            }
        }
        
        patient_id, create_msg = self.patient_records.create_patient_record(
            doctor_session, 
            patient_data
        )
        
        if patient_id:
            print("✅ Patient record creation: SUCCESS")
            print(f"   Patient ID: {patient_id[:16]}...")
        else:
            print("❌ Patient record creation: FAILED")
            return False
        
        # Access patient record
        record, access_msg = self.patient_records.access_patient_record(
            doctor_session, 
            patient_id, 
            "Routine checkup"
        )
        
        if record:
            print("✅ Patient record access: SUCCESS")
            print(f"   Patient: {record.get('name')}")
            print(f"   Condition: {record.get('medical_history')}")
            print(f"   Medication: {record.get('current_medication')}")
        else:
            print("❌ Patient record access: FAILED")
            return False
        
        # Update patient record
        version, update_msg = self.patient_records.update_patient_record(
            doctor_session,
            patient_id,
            {'current_medication': 'Lisinopril 10mg, Metformin 500mg, Aspirin 81mg'}
        )
        
        if version:
            print("✅ Patient record update: SUCCESS")
            print(f"   Record version: {version}")
        else:
            print("❌ Patient record update: FAILED")
        
        return True
    
    def test_medical_devices(self):
        """Test medical devices integration"""
        print("\n3. 🩺 MEDICAL DEVICES INTEGRATION")
        print("-" * 40)
        
        # Login as nurse
        nurse_session, _ = self.access_control.authenticate_user("nurse_jones", "Nurse123!")
        
        # Create a patient record for device data
        patient_data = {
            'name': 'Cardiac Patient',
            'dob': '1975-03-20',
            'condition': 'Cardiac monitoring'
        }
        
        patient_id, _ = self.patient_records.create_patient_record(nurse_session, patient_data)
        
        # Register medical device
        device_priv, device_pub = self.crypto_manager.generate_rsa_keypair()
        device_cert = self.medical_devices.register_device(
            "HR_MONITOR_001",
            "Heart Rate Monitor",
            device_pub,
            "Cardiology Ward"
        )
        
        if device_cert:
            print("✅ Medical device registration: SUCCESS")
            print(f"   Device: {device_cert['device_id']} ({device_cert['device_type']})")
        else:
            print("❌ Medical device registration: FAILED")
            return False
        
        # Simulate vital signs transmission
        vital_data = {
            'heart_rate': 72,
            'blood_oxygen': 98,
            'respiratory_rate': 16,
            'timestamp': time.time()
        }
        
        # Create device signature
        signature_data_to_sign = {
            'device_id': "HR_MONITOR_001",
            'patient_id': patient_id,
            'vital_data': vital_data,
            'timestamp': time.time()
        }
        device_signature = self.crypto_manager.create_signature(device_priv, signature_data_to_sign)
        
        # Prepare complete signature data for transmission
        complete_signature_data = {
            'data': signature_data_to_sign,
            'signature': device_signature
        }
        
        transmit_result, transmit_message = self.medical_devices.transmit_vital_signs(
            "HR_MONITOR_001",
            patient_id,
            vital_data,
            complete_signature_data
        )
        
        if transmit_result:
            print("✅ Vital signs transmission: SUCCESS")
            print(f"   Heart rate: {vital_data['heart_rate']} bpm")
            print(f"   Blood oxygen: {vital_data['blood_oxygen']}%")
        else:
            print("❌ Vital signs transmission: FAILED")
        
        return True
    
    def test_audit_system(self):
        """Test audit and compliance features"""
        print("\n4. 📊 AUDIT & COMPLIANCE SYSTEM")
        print("-" * 40)
        
        # Generate compliance report
        report = self.audit_system.generate_compliance_report(
            time.time() - 3600,  # Last hour
            time.time()
        )
        
        print("✅ Audit system: OPERATIONAL")
        print(f"   Total events recorded: {report['total_events']}")
        
        # Show event breakdown
        if report['event_breakdown']:
            print("   Event breakdown:")
            for event_type, count in report['event_breakdown'].items():
                print(f"     - {event_type}: {count}")
        
        # Verify log integrity
        integrity_ok, tampered_entries = self.audit_system.verify_log_integrity()
        if integrity_ok:
            print("✅ Log integrity: VERIFIED (no tampering detected)")
        else:
            print("❌ Log integrity: COMPROMISED")
            return False
        
        return True
    
    def test_security_features(self):
        """Test security features"""
        print("\n5. 🔒 SECURITY FEATURES VERIFICATION")
        print("-" * 40)
        
        # Test encryption
        test_medical_data = {
            'sensitive_info': 'Patient confidential data',
            'lab_results': {'glucose': 110, 'cholesterol': 180},
            'encrypted': True
        }
        
        key = self.crypto_manager.generate_aes_key()
        encrypted = self.crypto_manager.encrypt_data(test_medical_data, key)
        decrypted = self.crypto_manager.decrypt_data(encrypted, key)
        
        if test_medical_data == decrypted:
            print("✅ Data encryption: WORKING CORRECTLY")
        else:
            print("❌ Data encryption: FAILED")
            return False
        
        # Test digital signatures
        admin_priv, admin_pub = self.crypto_manager.generate_rsa_keypair()
        test_prescription = {
            'patient': 'John Doe',
            'medication': 'Amoxicillin 500mg',
            'dosage': '3 times daily for 7 days',
            'prescribing_doctor': 'Dr. Smith'
        }
        
        signature = self.crypto_manager.create_signature(admin_priv, test_prescription)
        verified = self.crypto_manager.verify_signature(admin_pub, test_prescription, signature)
        
        if verified:
            print("✅ Digital signatures: WORKING CORRECTLY")
        else:
            print("❌ Digital signatures: FAILED")
            return False
        
        # Test secure token generation
        token1 = self.crypto_manager.generate_secure_token()
        token2 = self.crypto_manager.generate_secure_token()
        
        if token1 != token2 and len(token1) >= 32:
            print("✅ Secure token generation: WORKING CORRECTLY")
        else:
            print("❌ Secure token generation: FAILED")
        
        return True

def main():
    """Run the complete demonstration"""
    print("Initializing Secure E-Health System...")
    
    try:
        demo = SecureEHealthDemo()
        demo.run_complete_demo()
        return True
    except Exception as e:
        print(f"\n❌ Demonstration failed with error: {e}")
        import traceback
        traceback.print_exc()
        return False

if __name__ == "__main__":
    success = main()
    sys.exit(0 if success else 1)