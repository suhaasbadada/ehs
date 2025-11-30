import time
import json
import hashlib

class MedicalDeviceManager:
    def __init__(self, crypto_manager, audit_system):
        self.crypto_manager = crypto_manager
        self.audit_system = audit_system
        self.registered_devices = {}
        self.device_data = {}
    
    def register_device(self, device_id, device_type, public_key, owner):
        """Register a new medical device"""
        device_certificate = {
            'device_id': device_id,
            'device_type': device_type,
            'public_key': public_key,
            'owner': owner,
            'registered_at': time.time(),
            'is_active': True,
            'certificate_hash': self._generate_certificate_hash(device_id, public_key)
        }
        
        self.registered_devices[device_id] = device_certificate
        
        self.audit_system.log_event(
            "DEVICE_REGISTERED",
            "system",
            f"Registered {device_type} device: {device_id}",
            severity="INFO"
        )
        
        return device_certificate
    
    def transmit_vital_signs(self, device_id, patient_id, vital_data, signature_data):
        """Transmit and store vital signs from medical device"""
        if device_id not in self.registered_devices:
            return False, "Device not registered"
        
        device = self.registered_devices[device_id]
        
        # Use the same data structure for verification as was signed
        verification_data = signature_data
        
        print(f"DEBUG: Verifying signature data")
        print(f"DEBUG: Using signature: {signature_data['signature'][:50]}...")
        
        # Verify device signature
        if not self.crypto_manager.verify_signature(
            device['public_key'], 
            verification_data['data'], 
            signature_data['signature']
        ):
            self.audit_system.log_event(
                "DEVICE_SIGNATURE_INVALID",
                "system",
                f"Invalid signature from device {device_id}",
                patient_id=patient_id,
                severity="HIGH"
            )
            return False, "Invalid device signature"
        
        # Store vital data
        if patient_id not in self.device_data:
            self.device_data[patient_id] = []
        
        data_record = {
            'timestamp': time.time(),
            'device_id': device_id,
            'vital_data': vital_data,
            'data_hash': self._hash_data(vital_data)
        }
        
        self.device_data[patient_id].append(data_record)
        
        self.audit_system.log_event(
            "VITAL_SIGNS_RECEIVED",
            "system",
            f"Received vital signs from {device_id} for patient {patient_id}",
            patient_id=patient_id
        )
        
        return True, "Vital signs recorded successfully"
    
    def get_patient_vitals(self, session_token, patient_id, hours_back=24):
        """Retrieve patient vital signs"""
        if patient_id not in self.device_data:
            return None, "No vital data found"
        
        cutoff_time = time.time() - (hours_back * 3600)
        recent_data = [
            record for record in self.device_data[patient_id] 
            if record['timestamp'] >= cutoff_time
        ]
        
        return recent_data, "Data retrieved successfully"
    
    def _generate_certificate_hash(self, device_id, public_key):
        """Generate hash for device certificate"""
        data = f"{device_id}{public_key}{time.time()}"
        return hashlib.sha256(data.encode()).hexdigest()
    
    def _hash_data(self, data):
        """Generate data integrity hash"""
        if isinstance(data, dict):
            data = json.dumps(data, sort_keys=True)
        return hashlib.sha256(data.encode()).hexdigest()
