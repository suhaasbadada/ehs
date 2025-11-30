# Security configuration settings
SECURITY_CONFIG = {
    'hash_algorithm': 'sha256',
    'rsa_key_size': 2048,
    'aes_key_size': 32,
    'token_expiry_hours': 24,
    'max_login_attempts': 3,
    'session_timeout_minutes': 30,
    'emergency_access_duration': 6,  # hours
}

# User roles and permissions
ROLES_CONFIG = {
    'physician': ['read_patient_data', 'write_patient_data', 'prescribe_medication'],
    'nurse': ['read_patient_data', 'update_vitals', 'administer_medication'],
    'receptionist': ['schedule_appointments', 'read_basic_info'],
    'patient': ['read_own_data', 'update_personal_info'],
    'admin': ['all_permissions', 'user_management', 'system_config']
}

# System constants
SYSTEM_CONSTANTS = {
    'min_password_length': 12,
    'audit_log_retention_days': 365,
    'backup_frequency_hours': 24
}
