# src/utils/validators.py
"""Input validation utilities"""

class Validators:
    """Validates user inputs"""
    
    @staticmethod
    def validate_email(email):
        """Validate email format"""
        import re
        pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
        return re.match(pattern, email) is not None
    
    @staticmethod
    def validate_password(password, min_length=12):
        """Validate password strength"""
        if len(password) < min_length:
            return False
        has_upper = any(c.isupper() for c in password)
        has_lower = any(c.islower() for c in password)
        has_digit = any(c.isdigit() for c in password)
        has_special = any(c in '!@#$%^&*' for c in password)
        return has_upper and has_lower and has_digit and has_special
    
    @staticmethod
    def validate_username(username):
        """Validate username format"""
        return 3 <= len(username) <= 20 and username.isalnum()
