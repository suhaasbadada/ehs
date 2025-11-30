# src/data/consent_manager.py
"""Consent management for patient data access"""

import time

class ConsentManager:
    """Manages patient consent for data access"""
    
    def __init__(self, crypto_manager):
        self.crypto_manager = crypto_manager
        self.consent_records = {}
    
    def grant_consent(self, patient_id, provider_id, duration_days=30):
        """Grant consent for data access"""
        consent_id = self.crypto_manager.generate_secure_token()
        expiry_time = time.time() + (duration_days * 24 * 3600)
        
        self.consent_records[consent_id] = {
            'patient_id': patient_id,
            'provider_id': provider_id,
            'granted_at': time.time(),
            'expires_at': expiry_time,
            'is_active': True
        }
        
        return consent_id
    
    def check_consent(self, patient_id, provider_id):
        """Check if valid consent exists"""
        for consent in self.consent_records.values():
            if (consent['patient_id'] == patient_id and 
                consent['provider_id'] == provider_id and 
                consent['is_active'] and 
                time.time() < consent['expires_at']):
                return True
        return False
    
    def revoke_consent(self, consent_id):
        """Revoke a consent record"""
        if consent_id in self.consent_records:
            self.consent_records[consent_id]['is_active'] = False
            return True
        return False
