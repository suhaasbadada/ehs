import sys
import time
from crypto_manager import CryptoManager
from access_control import AccessControlSystem
from audit_system import AuditSystem
from patient_records import PatientRecordsManager
from medical_devices import MedicalDeviceManager

class SecureEHealthSystem:
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
        
        # Create admin user
        self._create_default_admin()
    
    def _initialize_system_keys(self):
        """Initialize system cryptographic keys"""
        self.crypto_manager.audit_private_key, self.crypto_manager.audit_public_key = \
            self.crypto_manager.generate_rsa_keypair()
    
    def _create_default_admin(self):
        """Create default administrator account"""
        admin_private_key, admin_public_key = self.crypto_manager.generate_rsa_keypair()
        self.access_control.register_user(
            "admin", 
            "Admin123!",  # Fixed password
            "admin", 
            admin_public_key
        )
        print("Default admin user created: admin/Admin123!")
    
    def run_demo(self):
        """Run comprehensive system demonstration"""
        print("=== Secure E-Health System Demo ===")
        
        # 1. User authentication
        print("\n1. User Authentication")
        session_token, auth_message = self.access_control.authenticate_user("admin", "Admin123!")
        print(f"Authentication: {auth_message}")
        
        if not session_token:
            print("❌ Demo failed: Cannot authenticate admin user")
            print("Troubleshooting tips:")
            print("  - Check if user was registered properly")
            print("  - Verify password hashing")
            print("  - Run 'python debug_auth.py' for detailed debugging")
            return
        
        # Continue with the rest of the demo...
        # [Rest of the demo code remains the same]

def main():
    """Main application entry point"""
    system = SecureEHealthSystem()
    
    if len(sys.argv) > 1:
        if sys.argv[1] == "demo":
            system.run_demo()
        elif sys.argv[1] == "test":
            from test_system import EHealthSystemTester
            tester = EHealthSystemTester()
            tester.run_comprehensive_test()
        elif sys.argv[1] == "debug":
            from debug_auth import debug_authentication
            debug_authentication()
    else:
        print("Secure E-Health System")
        print("Usage:")
        print("  python main.py demo    - Run system demo")
        print("  python main.py test    - Run comprehensive tests")
        print("  python main.py debug   - Debug authentication")

if __name__ == "__main__":
    main()