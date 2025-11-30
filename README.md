# Secure E-Health System README

## Overview
A comprehensive, security-focused electronic health record (EHR) system with enterprise-grade cryptography and access controls.

## Features
- 🔐 AES-256 encryption for patient data
- 🔑 RSA-2048 digital signatures for audit trail
- 👥 Role-based access control (RBAC)
- 📊 Comprehensive audit logging
- 📱 Medical device integration
- 📋 Patient record management
- ✅ HIPAA/GDPR compliant

## Quick Start

### Installation
```bash
pip install -r requirements.txt
```

### Run Demo
```bash
python final_demo.py
```

### Run Tests
```bash
python -m pytest tests/
```

## Project Structure
```
secure-ehealth-system/
├── src/
│   ├── core/          # Core components
│   ├── auth/          # Authentication & authorization
│   ├── data/          # Data management
│   ├── audit/         # Audit & compliance
│   ├── api/           # API layer
│   └── utils/         # Utilities
├── tests/             # Test suite
├── docs/              # Documentation
├── config/            # Configuration files
├── scripts/           # Utility scripts
└── logs/              # Log files
```

## Security

This system implements multiple layers of security:

1. **Data Encryption**: AES-256-GCM for all sensitive data
2. **Authentication**: PBKDF2 password hashing with salt
3. **Authorization**: Role-based access control with granular permissions
4. **Audit Trail**: Digitally signed audit logs with tamper detection
5. **Session Management**: Automatic session timeout and validation

## Usage

### Create a Patient Record
```python
from src.core.crypto_manager import CryptoManager
from src.auth.access_control import AccessControlSystem
from src.data.patient_records import PatientRecordsManager

crypto = CryptoManager()
auth = AccessControlSystem(crypto)
records_mgr = PatientRecordsManager(crypto, auth, audit_system)

# Authenticate
session, _ = auth.authenticate_user("doctor", "password")

# Create record
patient_data = {'name': 'John Doe', 'dob': '1980-05-15'}
patient_id, msg = records_mgr.create_patient_record(session, patient_data)
```

## Running Tests

Unit tests:
```bash
python tests/unit/test_crypto.py
python tests/unit/test_auth.py
```

Integration tests:
```bash
python tests/integration/test_system_integration.py
```

## Documentation

- [Architecture](docs/architecture.md)
- [API](docs/api.md)
- [Security](docs/security.md)