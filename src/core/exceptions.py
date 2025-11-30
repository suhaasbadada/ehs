# src/core/exceptions.py
"""Custom exceptions for the E-Health system"""

class EHealthException(Exception):
    """Base exception for E-Health system"""
    pass

class AuthenticationError(EHealthException):
    """Raised when authentication fails"""
    pass

class AuthorizationError(EHealthException):
    """Raised when user lacks required permissions"""
    pass

class CryptographyError(EHealthException):
    """Raised when cryptographic operations fail"""
    pass

class DataIntegrityError(EHealthException):
    """Raised when data integrity check fails"""
    pass

class DeviceError(EHealthException):
    """Raised when medical device operations fail"""
    pass
