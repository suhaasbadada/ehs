# src/audit/log_manager.py
"""Log file management"""

import json
from datetime import datetime

class LogManager:
    """Manages audit log files"""
    
    def __init__(self, log_file="audit_log.json"):
        self.log_file = log_file
    
    def save_log(self, log_entry):
        """Save a log entry to file"""
        try:
            with open(self.log_file, 'a') as f:
                f.write(json.dumps(log_entry) + '\n')
            return True
        except Exception as e:
            print(f"Error saving log: {e}")
            return False
    
    def load_logs(self):
        """Load all logs from file"""
        logs = []
        try:
            with open(self.log_file, 'r') as f:
                for line in f:
                    if line.strip():
                        logs.append(json.loads(line))
        except FileNotFoundError:
            pass
        return logs
    
    def archive_logs(self, archive_file=None):
        """Archive old logs"""
        if not archive_file:
            archive_file = f"audit_log_archive_{datetime.now().strftime('%Y%m%d')}.json"
        
        logs = self.load_logs()
        with open(archive_file, 'w') as f:
            json.dump(logs, f, indent=2)
        
        return archive_file
