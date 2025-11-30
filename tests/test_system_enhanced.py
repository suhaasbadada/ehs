import sys
import time
from crypto_manager import CryptoManager
from access_control import AccessControlSystem
from audit_system import AuditSystem
from patient_records import PatientRecordsManager
from medical_devices import MedicalDeviceManager

class EnhancedEHealthSystemTester:
    def __init__(self):
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
    
    def _initialize_system_keys(self):
        """Initialize system cryptographic keys"""
        self.crypto_manager.audit_private_key, self.crypto_manager.audit_public_key = \
            self.crypto_manager.generate_rsa_keypair()
    
    def test_crypto_functions(self):
        """Test cryptographic functions"""
        print("🔐 TESTING CRYPTOGRAPHIC FUNCTIONS")
        print("=" * 50)
        
        try:
            # Test AES encryption/decryption
            print("1. Testing AES encryption...")
            test_data = {"message": "Hello, World!", "number": 42}
            key = self.crypto_manager.generate_aes_key()
            
            encrypted = self.crypto_manager.encrypt_data(test_data, key)
            decrypted = self.crypto_manager.decrypt_data(encrypted, key)
            
            assert test_data == decrypted, "Encryption/decryption failed"
            print("   ✓ AES encryption/decryption working correctly")
            
            # Test RSA signatures
            print("2. Testing RSA signatures...")
            priv_key, pub_key = self.crypto_manager.generate_rsa_keypair()
            signature = self.crypto_manager.create_signature(priv_key, test_data)
            verified = self.crypto_manager.verify_signature(pub_key, test_data, signature)
            
            assert verified, "Signature verification failed"
            print("   ✓ RSA signatures working correctly")
            
            # Test key encryption
            print("3. Testing key encryption...")
            test_key = self.crypto_manager.generate_aes_key()
            encrypted_key = self.crypto_manager.encrypt_key_for_storage(test_key)
            decrypted_key = self.crypto_manager.decrypt_key_from_storage(encrypted_key)
            
            assert test_key == decrypted_key, "Key encryption failed"
            print("   ✓ Key encryption working correctly")
            
            return True
            
        except Exception as e:
            print(f"   ✗ Cryptographic test failed: {e}")
            return False
    
    def test_authentication(self):
        """Test user registration and authentication"""
        print("\n🔐 TESTING AUTHENTICATION SYSTEM")
        print("=" * 50)
        
        try:
            # Generate keys for users
            admin_priv, admin_pub = self.crypto_manager.generate_rsa_keypair()
            doctor_priv, doctor_pub = self.crypto_manager.generate_rsa_keypair()
            
            # Register users
            print("1. Registering users...")
            admin_id = self.access_control.register_user("admin", "Admin123!", "admin", admin_pub)
            doctor_id = self.access_control.register_user("dr_smith", "Doctor123!", "physician", doctor_pub)
            
            print(f"   ✓ Admin user registered: {admin_id}")
            print(f"   ✓ Doctor user registered: {doctor_id}")
            
            # Test authentication
            print("\n2. Testing authentication...")
            
            # Successful login
            session_token, message = self.access_control.authenticate_user("admin", "Admin123!")
            if session_token:
                print(f"   ✓ Admin login successful: {message}")
                
                # Test permission checking with valid session
                has_permission, perm_message = self.access_control.check_permission(session_token, "read_patient_data")
                if has_permission:
                    print(f"   ✓ Permission check successful: {perm_message}")
                else:
                    print(f"   ✗ Permission check failed: {perm_message}")
                    return False
            else:
                print(f"   ✗ Admin login failed: {message}")
                return False
            
            # Failed login
            session_token, message = self.access_control.authenticate_user("admin", "WrongPassword")
            if not session_token:
                print(f"   ✓ Failed login handled correctly: {message}")
            else:
                print(f"   ✗ Failed login not handled properly")
                return False
            
            return True
            
        except Exception as e:
            print(f"   ✗ Authentication test failed: {e}")
            return False
    
    def test_patient_records(self):
        """Test patient record creation and access"""
        print("\n📋 TESTING PATIENT RECORDS SYSTEM")
        print("=" * 50)
        
        try:
            # Login as admin
            session_token, message = self.access_control.authenticate_user("admin", "Admin123!")
            if not session_token:
                print("   ✗ Cannot proceed - admin authentication failed")
                return False
            
            # Create patient record
            print("1. Creating patient record...")
            patient_data = {
                'name': 'John Doe',
                'dob': '1980-05-15',
                'medical_history': 'Hypertension, Type 2 Diabetes',
                'current_medication': 'Lisinopril 10mg, Metformin 500mg',
                'allergies': ['Penicillin', 'Sulfa']
            }
            
            patient_id, create_message = self.patient_records.create_patient_record(
                session_token, 
                patient_data
            )
            
            if patient_id:
                print(f"   ✓ Patient record created: {create_message}")
                print(f"   Patient ID: {patient_id}")
            else:
                print(f"   ✗ Patient record creation failed: {create_message}")
                return False
            
            # Access patient record
            print("\n2. Accessing patient record...")
            retrieved_data, access_message = self.patient_records.access_patient_record(
                session_token, 
                patient_id, 
                "Medical consultation"
            )
            
            if retrieved_data:
                print(f"   ✓ Record access successful: {access_message}")
                print(f"   Patient name: {retrieved_data.get('name')}")
                print(f"   Medical history: {retrieved_data.get('medical_history')}")
            else:
                print(f"   ✗ Record access failed: {access_message}")
                return False
            
            # Update patient record
            print("\n3. Updating patient record...")
            version, update_message = self.patient_records.update_patient_record(
                session_token,
                patient_id,
                {'current_medication': 'Lisinopril 10mg, Metformin 500mg, Aspirin 81mg'}
            )
            
            if version:
                print(f"   ✓ Record update successful: {update_message}")
                print(f"   New version: {version}")
            else:
                print(f"   ✗ Record update failed: {update_message}")
                return False
            
            return True
            
        except Exception as e:
            print(f"   ✗ Patient records test failed: {e}")
            import traceback
            traceback.print_exc()
            return False
    
    def test_medical_devices(self):
        """Test medical device integration"""
        print("\n🩺 TESTING MEDICAL DEVICES SYSTEM")
        print("=" * 50)
        
        try:
            # Login as admin
            session_token, message = self.access_control.authenticate_user("admin", "Admin123!")
            if not session_token:
                print("   ✗ Cannot proceed - admin authentication failed")
                return False
            
            # Create a patient record first
            patient_data = {
                'name': 'Test Patient',
                'dob': '1975-03-20',
                'medical_history': 'Cardiac patient'
            }
            
            patient_id, _ = self.patient_records.create_patient_record(session_token, patient_data)
            
            # Register medical device
            print("1. Registering medical device...")
            device_priv, device_pub = self.crypto_manager.generate_rsa_keypair()
            device_cert = self.medical_devices.register_device(
                "HR_MONITOR_001",
                "Heart Rate Monitor",
                device_pub,
                "Cardiology Ward"
            )
            
            if device_cert:
                print(f"   ✓ Device registered: {device_cert['device_id']}")
            else:
                print("   ✗ Device registration failed")
                return False
            
            # Simulate vital signs transmission
            print("\n2. Transmitting vital signs...")
            vital_data = {
                'heart_rate': 72,
                'blood_oxygen': 98,
                'timestamp': time.time()
            }
            
            # Create device signature
            signature_data = {
                'device_id': "HR_MONITOR_001",
                'patient_id': patient_id,
                'vital_data': vital_data,
                'timestamp': time.time()
            }
            device_signature = self.crypto_manager.create_signature(device_priv, signature_data)
            
            transmit_result, transmit_message = self.medical_devices.transmit_vital_signs(
                "HR_MONITOR_001",
                patient_id,
                vital_data,
                device_signature
            )
            
            if transmit_result:
                print(f"   ✓ Vital signs transmitted: {transmit_message}")
            else:
                print(f"   ✗ Transmission failed: {transmit_message}")
                return False
            
            return True
            
        except Exception as e:
            print(f"   ✗ Medical devices test failed: {e}")
            import traceback
            traceback.print_exc()
            return False
    
    def run_comprehensive_test(self):
        """Run all tests"""
        print("🚀 STARTING ENHANCED E-HEALTH SYSTEM TEST")
        print("=" * 60)
        
        tests = [
            ("Cryptographic Functions", self.test_crypto_functions),
            ("Authentication", self.test_authentication),
            ("Patient Records", self.test_patient_records),
            ("Medical Devices", self.test_medical_devices)
        ]
        
        results = []
        for test_name, test_func in tests:
            try:
                success = test_func()
                results.append((test_name, success))
                print(f"\n{'✅' if success else '❌'} {test_name} Test: {'PASSED' if success else 'FAILED'}")
                print("-" * 40)
            except Exception as e:
                print(f"\n❌ {test_name} Test: ERROR - {str(e)}")
                results.append((test_name, False))
                print("-" * 40)
        # Summary
        print("\n📈 TEST SUMMARY")
        print("=" * 30)
        passed = sum(1 for _, success in results if success)
        total = len(results)
        
        for test_name, success in results:
            status = "✅ PASS" if success else "❌ FAIL"
            print(f"{status} {test_name}")
        
        print(f"\nOverall: {passed}/{total} tests passed ({passed/total*100:.1f}%)")
        
        return all(success for _, success in results)

def main():
    """Run the enhanced test suite"""
    tester = EnhancedEHealthSystemTester()
    success = tester.run_comprehensive_test()
    
    if success:
        print("\n🎉 All tests passed! The system is working correctly.")
        sys.exit(0)
    else:
        print("\n💥 Some tests failed. Please check the implementation.")
        sys.exit(1)

if __name__ == "__main__":
    main()