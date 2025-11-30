# src/auth/permissions.py
"""Permission management utilities"""

from src.core.config import ROLES_CONFIG

class PermissionManager:
    """Manages user permissions"""
    
    @staticmethod
    def get_role_permissions(role):
        """Get all permissions for a given role"""
        return ROLES_CONFIG.get(role, [])
    
    @staticmethod
    def has_permission(role, permission):
        """Check if role has specific permission"""
        permissions = ROLES_CONFIG.get(role, [])
        return permission in permissions or 'all_permissions' in permissions
