# docs/api.md
# API Documentation

## Authentication Endpoints

### Register User
```python
AccessControlSystem.register_user(username, password, role, public_key)
```

### Authenticate
```python
AccessControlSystem.authenticate_user(username, password)
```

### Check Permission
```python
AccessControlSystem.check_permission(session_token, permission)
```

## Patient Records Endpoints

### Create Patient Record
```python
PatientRecordsManager.create_patient_record(session_token, patient_data)
```

### Access Patient Record
```python
PatientRecordsManager.access_patient_record(session_token, patient_id, purpose)
```

### Update Patient Record
```python
PatientRecordsManager.update_patient_record(session_token, patient_id, updates)
```

## Medical Devices Endpoints

### Register Device
```python
MedicalDeviceManager.register_device(device_id, device_type, public_key, owner)
```

### Transmit Vital Signs
```python
MedicalDeviceManager.transmit_vital_signs(device_id, patient_id, vital_data, signature_data)
```
