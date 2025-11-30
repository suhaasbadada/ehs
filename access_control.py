import time
import hashlib
import os
import base64
from config import ROLES_CONFIG, SECURITY_CONFIG

class AccessControlSystem:
    def __init__(self, crypto_manager):
        self.crypto_manager = crypto_manager
        self.users = {}
        self.sessions = {}
        self.failed_attempts = {}
        self.emergency_access = {}
    
    def register_user(self, username, password, role, public_key):
        """Register a new user with role-based permissions"""
        if role not in ROLES_CONFIG:
            raise ValueError(f"Invalid role: {role}")
        
        # Generate salt and hash password
        salt = os.urandom(32)
        password_hash = self._hash_password(password, salt)
        
        # Use simple hash for user ID
        user_id = self.crypto_manager.hash_sensitive_data(username + str(time.time()))
        
        self.users[username] = {
            'user_id': user_id,
            'password_hash': password_hash,
            'salt': salt,
            'role': role,
            'public_key': public_key,
            'created_at': time.time(),
            'is_active': True
        }
        
        print(f"DEBUG: Registered user '{username}' with role '{role}'")
        return user_id
    
    def authenticate_user(self, username, password):
        """Authenticate user and create session"""
        print(f"DEBUG: Attempting authentication for user '{username}'")
        
        if username not in self.users:
            print(f"DEBUG: User '{username}' not found")
            return None, "User not found"
        
        user = self.users[username]
        
        # Check failed attempts
        if self.failed_attempts.get(username, 0) >= SECURITY_CONFIG['max_login_attempts']:
            return None, "Account locked due to too many failed attempts"
        
        # Verify password
        if not self._verify_password(password, user['password_hash'], user['salt']):
            self.failed_attempts[username] = self.failed_attempts.get(username, 0) + 1
            return None, "Invalid credentials"
        
        # Reset failed attempts on successful login
        self.failed_attempts[username] = 0
        
        # Create session
        session_token = self.crypto_manager.generate_secure_token()
        session_data = {
            'user_id': user['user_id'],
            'username': username,
            'role': user['role'],
            'login_time': time.time(),
            'last_activity': time.time()
        }
        
        self.sessions[session_token] = session_data
        print(f"DEBUG: Authentication successful for '{username}'")
        return session_token, "Authentication successful"
    
    def check_permission(self, session_token, permission):
        """Check if user has specific permission"""
        if session_token not in self.sessions:
            return False, "Invalid session"
            
        session = self.sessions[session_token]
        
        # Check session timeout
        if time.time() - session['last_activity'] > SECURITY_CONFIG['session_timeout_minutes'] * 60:
            del self.sessions[session_token]
            return False, "Session expired"
        
        # Update last activity
        session['last_activity'] = time.time()
        
        user_role = session['role']
        user_permissions = ROLES_CONFIG.get(user_role, [])
        
        if permission in user_permissions or 'all_permissions' in user_permissions:
            return True, "Permission granted"
        
        return False, "Insufficient permissions"
    
    def _hash_password(self, password, salt):
        """Hash password with salt"""
        return hashlib.pbkdf2_hmac('sha256', password.encode(), salt, 100000)
    
    def _verify_password(self, password, stored_hash, salt):
        """Verify password against stored hash"""
        test_hash = self._hash_password(password, salt)
        return test_hash == stored_hash