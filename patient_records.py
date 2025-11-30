import time
import json
from access_control import AccessControlSystem

class PatientRecordsManager:
    def __init__(self, crypto_manager, access_control, audit_system):
        self.crypto_manager = crypto_manager
        self.access_control = access_control
        self.audit_system = audit_system
        self.patient_records = {}
        self.consent_records = {}
    
    def create_patient_record(self, session_token, patient_data):
        """Create new patient record with encryption and access controls"""
        # Check permission
        has_permission, message = self.access_control.check_permission(
            session_token, 'write_patient_data'
        )
        if not has_permission:
            self.audit_system.log_event(
                "UNAUTHORIZED_ACCESS_ATTEMPT",
                self.access_control.sessions[session_token]['user_id'],
                "Attempt to create patient record without permission",
                severity="HIGH"
            )
            return None, message
        
        # Generate patient ID
        patient_id = self._generate_patient_id(patient_data)
        
        # Encrypt sensitive data
        encryption_key = self.crypto_manager.generate_aes_key()
        encrypted_data = self.crypto_manager.encrypt_data(patient_data, encryption_key)
        
        # Create record with access controls
        record = {
            'patient_id': patient_id,
            'encrypted_data': encrypted_data,
            'encryption_key_encrypted': self.crypto_manager.encrypt_key_for_storage(encryption_key),
            'access_controls': {
                'allowed_roles': ['physician', 'nurse', 'admin'],
                'emergency_access': True,
                'consent_required': True
            },
            'metadata': {
                'created_by': self.access_control.sessions[session_token]['user_id'],
                'created_at': time.time(),
                'last_modified': time.time(),
                'version': 1
            },
            'audit_trail': []
        }
        
        self.patient_records[patient_id] = record
        
        # Log creation
        self.audit_system.log_event(
            "PATIENT_RECORD_CREATED",
            self.access_control.sessions[session_token]['user_id'],
            f"Created record for patient {patient_id}",
            patient_id=patient_id
        )
        
        return patient_id, "Patient record created successfully"
    
    def access_patient_record(self, session_token, patient_id, purpose=None):
        """Access patient record with comprehensive security checks"""
        # Check permission
        has_permission, message = self.access_control.check_permission(
            session_token, 'read_patient_data'
        )
        if not has_permission:
            self.audit_system.log_event(
                "UNAUTHORIZED_ACCESS_ATTEMPT",
                self.access_control.sessions[session_token]['user_id'],
                f"Attempt to access patient {patient_id} without permission",
                patient_id=patient_id,
                severity="HIGH"
            )
            return None, message
        
        if patient_id not in self.patient_records:
            return None, "Patient record not found"
        
        record = self.patient_records[patient_id]
        user_session = self.access_control.sessions[session_token]
        
        # Check consent if required (bypass for admin or creator)
        if record['access_controls']['consent_required']:
            is_creator = record['metadata']['created_by'] == user_session['user_id']
            is_admin = user_session['role'] == 'admin'
            if not is_creator and not is_admin:
                consent_granted = self._check_consent(patient_id, user_session['user_id'])
                if not consent_granted:
                    return None, "Patient consent required for access"
        
        # Decrypt data
        try:
            encryption_key = self.crypto_manager.decrypt_key_from_storage(
                record['encryption_key_encrypted']
            )
            decrypted_data = self.crypto_manager.decrypt_data(
                record['encrypted_data'], 
                encryption_key
            )
        except Exception as e:
            self.audit_system.log_event(
                "DECRYPTION_ERROR",
                user_session['user_id'],
                f"Failed to decrypt patient data: {str(e)}",
                patient_id=patient_id,
                severity="HIGH"
            )
            return None, f"Data decryption failed: {str(e)}"
        
        # Log access
        self.audit_system.log_event(
            "PATIENT_RECORD_ACCESSED",
            user_session['user_id'],
            f"Accessed patient record for purpose: {purpose}",
            patient_id=patient_id
        )
        
        # Update audit trail in record
        record['audit_trail'].append({
            'timestamp': time.time(),
            'accessed_by': user_session['user_id'],
            'purpose': purpose,
            'action': 'read'
        })
        
        return decrypted_data, "Access granted"
    
    def update_patient_record(self, session_token, patient_id, updates):
        """Update patient record with version control"""
        has_permission, message = self.access_control.check_permission(
            session_token, 'write_patient_data'
        )
        if not has_permission:
            return None, message
        
        if patient_id not in self.patient_records:
            return None, "Patient record not found"
        
        record = self.patient_records[patient_id]
        user_session = self.access_control.sessions[session_token]
        
        # Get current data
        encryption_key = self.crypto_manager.decrypt_key_from_storage(
            record['encryption_key_encrypted']
        )
        current_data = self.crypto_manager.decrypt_data(
            record['encrypted_data'], 
            encryption_key
        )
        
        # Apply updates
        updated_data = {**current_data, **updates}
        
        # Re-encrypt data
        record['encrypted_data'] = self.crypto_manager.encrypt_data(
            updated_data, 
            encryption_key
        )
        
        # Update metadata
        record['metadata']['last_modified'] = time.time()
        record['metadata']['version'] += 1
        record['metadata']['modified_by'] = user_session['user_id']
        
        # Log update
        self.audit_system.log_event(
            "PATIENT_RECORD_UPDATED",
            user_session['user_id'],
            f"Updated patient record (version {record['metadata']['version']})",
            patient_id=patient_id
        )
        
        record['audit_trail'].append({
            'timestamp': time.time(),
            'modified_by': user_session['user_id'],
            'changes': list(updates.keys()),
            'action': 'update'
        })
        
        return record['metadata']['version'], "Record updated successfully"
    
    def grant_consent(self, patient_session_token, provider_user_id, duration_days=30):
        """Patient grants consent for data access"""
        patient_session = self.access_control.sessions.get(patient_session_token)
        if not patient_session or patient_session['role'] != 'patient':
            return False, "Invalid patient session"
        
        consent_id = self.crypto_manager.generate_secure_token()
        expiry_time = time.time() + (duration_days * 24 * 3600)
        
        self.consent_records[consent_id] = {
            'patient_id': patient_session['user_id'],
            'provider_id': provider_user_id,
            'granted_at': time.time(),
            'expires_at': expiry_time,
            'is_active': True
        }
        
        self.audit_system.log_event(
            "CONSENT_GRANTED",
            patient_session['user_id'],
            f"Granted consent to provider {provider_user_id}",
            severity="INFO"
        )
        
        return consent_id, "Consent granted successfully"
    
    def _generate_patient_id(self, patient_data):
        """Generate unique patient ID - FIXED VERSION"""
        identifier_data = f"{patient_data.get('name', '')}{patient_data.get('dob', '')}{time.time()}"
        # Now hash_sensitive_data returns a single string, not a tuple
        return self.crypto_manager.hash_sensitive_data(identifier_data)[:16]
    
    def _check_consent(self, patient_id, user_id):
        """Check if consent exists for data access"""
        for consent in self.consent_records.values():
            if (consent['patient_id'] == patient_id and 
                consent['provider_id'] == user_id and 
                consent['is_active'] and 
                time.time() < consent['expires_at']):
                return True
        return False
    
    def list_patients(self):
        """Debug method to list all patients"""
        return list(self.patient_records.keys())