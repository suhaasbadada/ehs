# src/utils/helpers.py
"""Helper functions"""

import hashlib
import json

class Helpers:
    """General helper functions"""
    
    @staticmethod
    def hash_string(s):
        """Hash a string"""
        return hashlib.sha256(s.encode()).hexdigest()
    
    @staticmethod
    def dict_to_json(d):
        """Convert dict to JSON string"""
        return json.dumps(d, ensure_ascii=False)
    
    @staticmethod
    def json_to_dict(s):
        """Convert JSON string to dict"""
        return json.loads(s)
