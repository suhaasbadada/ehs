# src/utils/constants.py
"""System constants"""

# Error messages
ERROR_MESSAGES = {
    'UNAUTHORIZED': 'Unauthorized access',
    'INVALID_CREDENTIALS': 'Invalid credentials',
    'SESSION_EXPIRED': 'Session expired',
    'PERMISSION_DENIED': 'Permission denied',
}

# Success messages
SUCCESS_MESSAGES = {
    'LOGIN_SUCCESS': 'Login successful',
    'LOGOUT_SUCCESS': 'Logout successful',
    'RECORD_CREATED': 'Record created successfully',
    'RECORD_UPDATED': 'Record updated successfully',
}

# API response codes
RESPONSE_CODES = {
    'SUCCESS': 200,
    'CREATED': 201,
    'BAD_REQUEST': 400,
    'UNAUTHORIZED': 401,
    'FORBIDDEN': 403,
    'NOT_FOUND': 404,
    'SERVER_ERROR': 500,
}
