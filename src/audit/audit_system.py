import time
import json
import hashlib
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding

class AuditSystem:
    def __init__(self, crypto_manager):
        self.crypto_manager = crypto_manager
        self.audit_log = []
        self.log_file = "logs/audit_log.json"
    
    def log_event(self, event_type, user_id, description, patient_id=None, severity="INFO"):
        """Log security event with digital signature"""
        log_entry = {
            'timestamp': time.time(),
            'event_id': self._generate_event_id(),
            'event_type': event_type,
            'user_id': user_id,
            'patient_id': patient_id,
            'description': description,
            'severity': severity,
            'ip_address': self._get_client_ip()
        }
        
        # Create digital signature for log entry if audit keys are available
        if hasattr(self.crypto_manager, 'audit_private_key') and self.crypto_manager.audit_private_key:
            signature = self.crypto_manager.create_signature(
                self.crypto_manager.audit_private_key, 
                log_entry
            )
            log_entry['signature'] = signature
        
        self.audit_log.append(log_entry)
        self._save_to_file(log_entry)
        
        return log_entry['event_id']
    
    def query_logs(self, start_time=None, end_time=None, user_id=None, 
                  event_type=None, patient_id=None):
        """Query audit logs with filters"""
        results = self.audit_log
        
        if start_time:
            results = [log for log in results if log['timestamp'] >= start_time]
        if end_time:
            results = [log for log in results if log['timestamp'] <= end_time]
        if user_id:
            results = [log for log in results if log.get('user_id') == user_id]
        if event_type:
            results = [log for log in results if log['event_type'] == event_type]
        if patient_id:
            results = [log for log in results if log.get('patient_id') == patient_id]
        
        return results
    
    def verify_log_integrity(self):
        """Verify digital signatures of all log entries"""
        tampered_entries = []
        
        # Skip verification if no audit keys
        if not hasattr(self.crypto_manager, 'audit_public_key') or not self.crypto_manager.audit_public_key:
            return True, []
        
        for entry in self.audit_log:
            # Create copy without signature for verification
            entry_copy = entry.copy()
            signature = entry_copy.pop('signature', None)
            
            if signature and not self.crypto_manager.verify_signature(
                self.crypto_manager.audit_public_key, 
                entry_copy, 
                signature
            ):
                tampered_entries.append(entry['event_id'])
        
        return len(tampered_entries) == 0, tampered_entries
    
    def generate_compliance_report(self, start_date, end_date):
        """Generate compliance report for regulatory purposes"""
        relevant_logs = self.query_logs(start_date, end_date)
        
        report = {
            'period': {'start': start_date, 'end': end_date},
            'total_events': len(relevant_logs),
            'event_breakdown': self._categorize_events(relevant_logs),
            'user_activity': self._analyze_user_activity(relevant_logs),
            'security_incidents': self._identify_security_incidents(relevant_logs)
        }
        
        return report
    
    def _generate_event_id(self):
        """Generate unique event ID"""
        return hashlib.sha256(f"{time.time()}{len(self.audit_log)}".encode()).hexdigest()[:16]
    
    def _get_client_ip(self):
        """Get client IP address (placeholder for real implementation)"""
        return "192.168.1.100"
    
    def _save_to_file(self, log_entry):
        """Save log entry to file (append mode)"""
        try:
            with open(self.log_file, 'a') as f:
                f.write(json.dumps(log_entry) + '\n')
        except Exception as e:
            print(f"Error saving audit log: {e}")
    
    def _categorize_events(self, logs):
        """Categorize events by type"""
        categories = {}
        for log in logs:
            categories[log['event_type']] = categories.get(log['event_type'], 0) + 1
        return categories
    
    def _analyze_user_activity(self, logs):
        """Analyze user activity patterns"""
        user_activity = {}
        for log in logs:
            user_id = log.get('user_id')
            if user_id:
                user_activity[user_id] = user_activity.get(user_id, 0) + 1
        return user_activity
    
    def _identify_security_incidents(self, logs):
        """Identify potential security incidents"""
        incidents = []
        for log in logs:
            if log.get('severity') in ['HIGH', 'CRITICAL']:
                incidents.append(log)
        return incidents
