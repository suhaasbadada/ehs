# Run Commands for Secure E-Health System

## Main Demonstration
```bash
python final_demo.py
```
Runs a complete end-to-end demonstration of the entire system including:
- User authentication and authorization
- Patient record management (create, read, update)
- Medical device integration
- Audit and compliance reporting
- Security features verification

**Expected Output**: All tests pass with ✅ indicators for each subsystem

## Individual Unit Tests
Tests AES encryption/decryption and RSA signature generation/verification

### Test Authentication System
```bash
python tests/unit/test_auth.py
```
Tests user registration, authentication, and permission checking

### Test Patient Records Management
```bash
python tests/unit/test_patient_records.py
```
Tests patient record creation, access, and updates

### Test Medical Device Integration
```bash
python tests/unit/test_medical_devices.py
```
Tests device registration and vital signs transmission

## Integration Tests

### System Integration Test
```bash
python tests/integration/test_system_integration.py
```
Tests all components working together in a complete workflow

### Security Features Test
```bash
python tests/integration/test_security.py
```
Tests password security and encryption verification

## Setup and Deployment

### Setup Development Environment
```bash
python scripts/setup.py
```
Installs all required dependencies from requirements.txt

## Project Entry Points

### Main Application
```bash
python main.py
```
Simple entry point (outputs startup message)

### Complete Demo
Please refer to `STRUCTURE.md` and `README.md` for canonical run commands and development instructions. This file has been consolidated into the primary documentation to avoid duplication.

Canonical quick commands:

```powershell
python final_demo.py
python -m pytest -q
pip install -r requirements.txt
```
tree src/
tree tests/
```

## Project Structure Summary

```
secure-ehealth-system/
├── src/                    # Main source code
│   ├── core/              # Crypto and config
│   ├── auth/              # Authentication
│   ├── data/              # Patient data
│   ├── audit/             # Audit system
│   ├── api/               # API layer
│   └── utils/             # Utilities
├── tests/                 # Test suite
├── docs/                  # Documentation
├── config/                # Configuration
├── logs/                  # Log storage
├── scripts/               # Utility scripts
├── final_demo.py         # Main demo
└── requirements.txt      # Dependencies
```

## Key Features

✅ **Encryption**: AES-256-GCM for all sensitive data
✅ **Authentication**: PBKDF2 password hashing with salt
✅ **Authorization**: Role-based access control (RBAC)
✅ **Audit Trail**: Digitally signed events with tamper detection
✅ **Medical Devices**: Secure device registration and vital signs transmission
✅ **Patient Records**: Encrypted storage with version control
✅ **Compliance**: HIPAA/GDPR compliant logging

## Default Test Credentials

```
Admin User:
  Username: admin
  Password: Admin123!
  Role: Administrator

Doctor User:
  Username: dr_smith
  Password: Doctor123!
  Role: Physician

Nurse User:
  Username: nurse_jones
  Password: Nurse123!
  Role: Nurse
```

## Expected Demo Output

The `final_demo.py` should show:
- ✅ All 5 subsystems passing
- ✅ 6 audit events logged
- ✅ No tampering detected in audit logs
- ✅ All security features working correctly

## Troubleshooting

### Import Errors
- Ensure you're running from the project root directory
- Verify all files in `src/` have proper `__init__.py` files

### Dependencies Missing
```bash
pip install -r requirements.txt
```

### Permission Errors
Check that the system has write access to create log files

### Audit Log Issues
The `audit_log.json` file is created in the logs directory automatically

## Next Steps

1. Review the architecture in `docs/architecture.md`
2. Check API documentation in `docs/api.md`
3. Explore security features in `docs/security.md`
4. Run unit tests for specific components
5. Integrate with your application as needed
