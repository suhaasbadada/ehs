# Project Structure Overview

## Complete Directory Structure

```
secure-ehealth-system/
│
├── src/                          # Source code
│   ├── __init__.py
│   ├── core/                     # Core components
│   │   ├── __init__.py
│   │   ├── crypto_manager.py     # Cryptographic operations (AES, RSA, hashing)
│   │   ├── config.py             # Configuration and role definitions
│   │   └── exceptions.py         # Custom exceptions
│   │
│   ├── auth/                     # Authentication & Authorization
│   │   ├── __init__.py
│   │   ├── access_control.py     # User registration and authentication
│   │   ├── session_manager.py    # Session management
│   │   └── permissions.py        # Permission management
│   │
│   ├── data/                     # Data Management
│   │   ├── __init__.py
│   │   ├── patient_records.py    # Patient record CRUD
│   │   ├── medical_devices.py    # Medical device integration
│   │   └── consent_manager.py    # Consent management
│   │
│   ├── audit/                    # Audit & Compliance
│   │   ├── __init__.py
│   │   ├── audit_system.py       # Audit logging and verification
│   │   ├── compliance_reporter.py # Compliance reports
│   │   └── log_manager.py        # Log file management
│   │
│   ├── api/                      # API Layer
│   │   ├── __init__.py
│   │   ├── routes.py             # API routes
│   │   ├── middleware.py         # Middleware
│   │   └── schemas.py            # Request/response schemas
│   │
│   └── utils/                    # Utilities
│       ├── __init__.py
│       ├── validators.py         # Input validation
│       ├── helpers.py            # Helper functions
│       └── constants.py          # Constants
│
├── tests/                        # Test Suite
│   ├── __init__.py
│   ├── unit/                     # Unit tests
│   │   ├── __init__.py
│   │   ├── test_crypto.py        # Crypto tests
│   │   ├── test_auth.py          # Auth tests
│   │   ├── test_patient_records.py
│   │   └── test_medical_devices.py
│   │
│   ├── integration/              # Integration tests
│   │   ├── __init__.py
│   │   ├── test_system_integration.py
│   │   └── test_security.py
│   │
│   └── fixtures/                 # Test fixtures
│       ├── __init__.py
│       ├── test_data.py          # Sample test data
│       └── mock_devices.py       # Mock medical devices
│
├── docs/                         # Documentation
│   ├── architecture.md           # System architecture
│   ├── api.md                    # API documentation
│   └── security.md               # Security documentation
│
├── scripts/                      # Utility Scripts
│   ├── setup.py                  # Development setup
│   ├── deploy.py                 # Deployment script
│   └── backup.py                 # Backup script
│
├── config/                       # Configuration Files
│   ├── development.yaml          # Dev config
│   ├── production.yaml           # Production config
│   └── security_policies.yaml    # Security policies
│
├── logs/                         # Log Storage
│   ├── audit/                    # Audit logs
│   └── system/                   # System logs
│
├── final_demo.py                 # Complete system demonstration
├── main.py                       # Entry point
├── requirements.txt              # Python dependencies
├── README.md                      # Project README
└── .gitignore                    # Git ignore rules
```

## Component Relationships

```
┌─────────────────────────────────────────────────┐
│          API Layer (src/api/)                   │
└──────────────────┬──────────────────────────────┘
                   │
┌─────────────────┴──────────────────────────┐
│  Authentication Layer (src/auth/)          │
│  - AccessControlSystem                     │
│  - SessionManager                          │
│  - PermissionManager                       │
└──────────┬─────────────────────────────────┘
           │
    ┌──────┴──────┐
    │             │
┌───▼────────┐  ┌─▼──────────────┐
│Core Layer  │  │Data Layer      │
│(src/core/) │  │(src/data/)     │
├────────────┤  ├────────────────┤
│CryptoMgr   │  │PatientRecords  │
│Config      │  │MedicalDevices  │
│Exceptions  │  │ConsentManager  │
└────────────┘  └────────┬───────┘
                         │
                    ┌────▼──────────────┐
                    │Audit Layer        │
                    │(src/audit/)       │
                    ├───────────────────┤
                    │AuditSystem        │
                    │ComplianceReporter │
                    │LogManager         │
                    └───────────────────┘
```

## Key Features by Module

### Core (`src/core/`)
- AES-256-GCM encryption/decryption
- RSA-2048 key generation and signatures
- PBKDF2 password hashing
- Configuration management
- Custom exception hierarchy

### Authentication (`src/auth/`)
- User registration with role assignment
- Secure authentication with password verification
- Session management with timeouts
- Role-based permission checking
- Failed login attempt tracking

### Data Management (`src/data/`)
- Encrypted patient record storage
- Version control for records
- Medical device registration
- Vital signs transmission with signatures
- Consent-based access control

### Audit & Compliance (`src/audit/`)
- Comprehensive event logging
- Digital signature verification for audit trails
- Tampering detection
- Compliance reporting (HIPAA, GDPR)
- Log file management and archival

### Utilities (`src/utils/`)
- Email and password validation
- Input sanitization
- Cryptographic helpers
- System constants and messages

## Running the System

### Complete Demo
```bash
python final_demo.py
```

### Unit Tests
```bash
python tests/unit/test_crypto.py
python tests/unit/test_auth.py
python tests/unit/test_patient_records.py
python tests/unit/test_medical_devices.py
```

### Integration Tests
```bash
python tests/integration/test_system_integration.py
python tests/integration/test_security.py
```

### Setup Development Environment
```bash
python scripts/setup.py
```

## Module Dependencies

- **cryptography**: Cryptographic operations
- **pyyaml**: Configuration file parsing (optional)
- **pytest**: Testing framework (optional)

See `requirements.txt` for complete list.
