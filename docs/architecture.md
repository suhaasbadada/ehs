# docs/architecture.md
# System Architecture

## Overview
Secure E-Health System is a comprehensive healthcare information system with enterprise-grade security features.

## Components

### Core (`src/core/`)
- **CryptoManager**: Handles all cryptographic operations (AES, RSA, hashing)
- **Config**: System configuration and role definitions
- **Exceptions**: Custom exception classes

### Authentication (`src/auth/`)
- **AccessControlSystem**: User registration, authentication, and authorization
- **SessionManager**: Manages user sessions
- **PermissionManager**: Manages role-based permissions

### Data Management (`src/data/`)
- **PatientRecordsManager**: CRUD operations for patient records with encryption
- **MedicalDeviceManager**: Device registration and vital signs management
- **ConsentManager**: Manages patient consent for data access

### Audit & Compliance (`src/audit/`)
- **AuditSystem**: Logs all security events with digital signatures
- **ComplianceReporter**: Generates compliance reports
- **LogManager**: Manages audit log files

### Utilities (`src/utils/`)
- **Validators**: Input validation utilities
- **Helpers**: Helper functions
- **Constants**: System constants

## Security Features
- AES-256 encryption for sensitive data
- RSA-2048 digital signatures
- PBKDF2 password hashing
- Role-based access control (RBAC)
- Comprehensive audit logging
- Session management with timeouts
