# tests/fixtures/mock_devices.py
"""Mock medical devices for testing"""

class MockHeartRateMonitor:
    def __init__(self, device_id="MOCK_HR_001"):
        self.device_id = device_id
        self.heart_rate = 72
        self.blood_oxygen = 98
    
    def get_readings(self):
        return {
            'heart_rate': self.heart_rate,
            'blood_oxygen': self.blood_oxygen
        }

class MockBloodPressureMonitor:
    def __init__(self, device_id="MOCK_BP_001"):
        self.device_id = device_id
        self.systolic = 120
        self.diastolic = 80
    
    def get_readings(self):
        return {
            'systolic': self.systolic,
            'diastolic': self.diastolic
        }
