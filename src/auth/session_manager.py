# src/auth/session_manager.py
"""Session management utilities"""

import time

class SessionManager:
    """Manages user sessions"""
    
    @staticmethod
    def is_session_valid(session, timeout_minutes):
        """Check if session is still valid"""
        return time.time() - session['last_activity'] <= timeout_minutes * 60
    
    @staticmethod
    def update_last_activity(session):
        """Update session last activity timestamp"""
        session['last_activity'] = time.time()
