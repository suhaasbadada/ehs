# tests/fixtures/test_data.py
"""Test data fixtures"""

SAMPLE_PATIENT_DATA = {
    'name': 'John Doe',
    'dob': '1980-05-15',
    'ssn': '123-45-6789',
    'medical_history': 'Hypertension, Type 2 Diabetes',
    'current_medication': ['Lisinopril 10mg', 'Metformin 500mg'],
    'allergies': ['Penicillin', 'Sulfa']
}

SAMPLE_DEVICE_DATA = {
    'device_id': 'HR_MONITOR_001',
    'device_type': 'Heart Rate Monitor',
    'location': 'Cardiology Ward'
}

SAMPLE_VITAL_SIGNS = {
    'heart_rate': 72,
    'blood_oxygen': 98,
    'blood_pressure': '120/80',
    'temperature': 98.6
}

TEST_CREDENTIALS = {
    'admin': {'username': 'admin', 'password': 'Admin123!', 'role': 'admin'},
    'doctor': {'username': 'dr_test', 'password': 'Doctor123!', 'role': 'physician'},
    'nurse': {'username': 'nurse_test', 'password': 'Nurse123!', 'role': 'nurse'},
}
