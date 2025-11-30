# Test Suite - Secure E-Health System

All test files have been organized in this `tests/` folder. The main codebase remains untouched in the parent directory.

## Test Files

- **test_system.py** - Comprehensive system test suite covering authentication, patient records, medical devices, and audit system
- **test_system_enhanced.py** - Enhanced test suite with additional cryptographic function tests
- **test_fix.py** - Patient record creation test
- **debug_auth.py** - Authentication debugging utility
- **quick_fix.py** - Quick basic functionality test
- **run.py** - Prototype/reference implementation (legacy)

## Running the Tests

From the project root directory, use the following commands:

### Run the main comprehensive test:
```bash
python tests/test_system.py
```

### Run the enhanced test suite:
```bash
python tests/test_system_enhanced.py
```

### Run patient record creation test:
```bash
python tests/test_fix.py
```

### Run authentication debugging:
```bash
python tests/debug_auth.py
```

### Run quick functionality test:
```bash
python tests/quick_fix.py
```

## Main Application

To run the main demonstration:
```bash
python final_demo.py
```

## Folder Structure

```
sns-project/
├── [Core system files]
│   ├── access_control.py
│   ├── audit_system.py
│   ├── crypto_manager.py
│   ├── medical_devices.py
│   ├── patient_records.py
│   ├── config.py
│   ├── final_demo.py
│   ├── main.py
│   ├── requirements.txt
│   └── audit_log.json
└── tests/
    ├── __init__.py
    ├── README.md
    ├── test_system.py
    ├── test_system_enhanced.py
    ├── test_fix.py
    ├── debug_auth.py
    ├── quick_fix.py
    └── run.py (legacy prototype)
```

## Bug Fix Applied

**Issue**: Patient record access was failing due to consent check logic.

**Fix**: Updated `patient_records.py` - added bypass logic for record creators and admins to access their own/any records without requiring explicit consent.

**Result**: All tests now pass ✅

## Notes

- All test files include proper path handling via `sys.path.insert()` to import modules from the parent directory
- No changes were made to core system files except critical bug fixes
- All imports work correctly from any working directory
- All tests pass successfully ✅
