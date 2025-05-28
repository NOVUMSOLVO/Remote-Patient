"""
Validation utilities for the RPM application
"""

import re
import string
from datetime import datetime, date

def validate_email(email):
    """Validate email format"""
    if not email:
        return False
    
    email_pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
    return re.match(email_pattern, email.strip()) is not None

def validate_password(password):
    """Validate password strength"""
    errors = []
    
    if not password:
        errors.append("Password is required")
        return errors
    
    if len(password) < 8:
        errors.append("Password must be at least 8 characters long")
    
    if len(password) > 128:
        errors.append("Password must be less than 128 characters")
    
    if not re.search(r'[A-Z]', password):
        errors.append("Password must contain at least one uppercase letter")
    
    if not re.search(r'[a-z]', password):
        errors.append("Password must contain at least one lowercase letter")
    
    if not re.search(r'\d', password):
        errors.append("Password must contain at least one number")
    
    if not re.search(r'[!@#$%^&*(),.?":{}|<>]', password):
        errors.append("Password must contain at least one special character")
    
    # Check for common passwords
    common_passwords = [
        'password', '123456', '123456789', 'qwerty', 'abc123',
        'password123', '12345678', '111111', '1234567890'
    ]
    
    if password.lower() in common_passwords:
        errors.append("Password is too common")
    
    return errors

def validate_nhs_number(nhs_number):
    """Validate NHS number format and checksum"""
    if not nhs_number:
        return False
    
    # Remove spaces and convert to string
    nhs_clean = str(nhs_number).replace(' ', '').replace('-', '')
    
    # Check length
    if len(nhs_clean) != 10:
        return False
    
    # Check if all digits
    if not nhs_clean.isdigit():
        return False
    
    # NHS number checksum validation
    try:
        digits = [int(d) for d in nhs_clean]
        
        # Calculate checksum
        total = 0
        for i in range(9):
            total += digits[i] * (10 - i)
        
        remainder = total % 11
        check_digit = 11 - remainder
        
        if check_digit == 11:
            check_digit = 0
        elif check_digit == 10:
            return False  # Invalid NHS number
        
        return check_digit == digits[9]
        
    except (ValueError, IndexError):
        return False

def validate_phone_number(phone):
    """Validate UK phone number format"""
    if not phone:
        return True  # Phone is optional
    
    # Remove common formatting
    phone_clean = re.sub(r'[\s\-\(\)]', '', phone)
    
    # UK phone number patterns
    uk_patterns = [
        r'^(\+44|0044|44)?[1-9]\d{8,9}$',  # General UK format
        r'^(\+44|0044|44)?7\d{9}$',        # Mobile
        r'^(\+44|0044|44)?20\d{8}$',       # London
        r'^(\+44|0044|44)?1\d{9}$'         # Other areas
    ]
    
    for pattern in uk_patterns:
        if re.match(pattern, phone_clean):
            return True
    
    return False

def validate_date_format(date_string, format_string='%Y-%m-%d'):
    """Validate date format"""
    if not date_string:
        return False
    
    try:
        datetime.strptime(date_string, format_string)
        return True
    except ValueError:
        return False

def validate_date_of_birth(dob_string):
    """Validate date of birth"""
    if not validate_date_format(dob_string):
        return False
    
    try:
        birth_date = datetime.strptime(dob_string, '%Y-%m-%d').date()
        today = date.today()
        
        # Check if date is not in the future
        if birth_date > today:
            return False
        
        # Check reasonable age limits (0-150 years)
        age = today.year - birth_date.year
        if today.month < birth_date.month or (today.month == birth_date.month and today.day < birth_date.day):
            age -= 1
        
        if age < 0 or age > 150:
            return False
        
        return True
        
    except ValueError:
        return False

def validate_medical_data(data_type, value, unit=None):
    """Validate medical measurement data"""
    validation_rules = {
        'blood_pressure': {
            'required_fields': ['systolic', 'diastolic'],
            'systolic_range': (70, 250),
            'diastolic_range': (40, 150),
            'units': ['mmHg']
        },
        'heart_rate': {
            'range': (30, 220),
            'units': ['bpm']
        },
        'glucose': {
            'range': (2.0, 30.0),  # mmol/L
            'units': ['mmol/L', 'mg/dL']
        },
        'weight': {
            'range': (1.0, 300.0),  # kg
            'units': ['kg', 'lbs']
        },
        'temperature': {
            'range': (32.0, 45.0),  # Celsius
            'units': ['°C', '°F']
        },
        'oxygen_saturation': {
            'range': (70, 100),  # percentage
            'units': ['%']
        }
    }
    
    if data_type not in validation_rules:
        return {'valid': False, 'errors': ['Unknown data type']}
    
    rules = validation_rules[data_type]
    errors = []
    
    # Validate unit
    if unit and 'units' in rules and unit not in rules['units']:
        errors.append(f'Invalid unit: {unit}. Expected one of: {", ".join(rules["units"])}')
    
    # Validate value based on data type
    if data_type == 'blood_pressure':
        if not isinstance(value, dict):
            errors.append('Blood pressure value must be an object with systolic and diastolic values')
        else:
            for field in rules['required_fields']:
                if field not in value:
                    errors.append(f'Missing required field: {field}')
                else:
                    field_value = value[field]
                    if not isinstance(field_value, (int, float)):
                        errors.append(f'{field} must be a number')
                    else:
                        range_key = f'{field}_range'
                        if range_key in rules:
                            min_val, max_val = rules[range_key]
                            if not (min_val <= field_value <= max_val):
                                errors.append(f'{field} must be between {min_val} and {max_val}')
    else:
        # Simple numeric validation
        if not isinstance(value, (int, float)):
            errors.append('Value must be a number')
        elif 'range' in rules:
            min_val, max_val = rules['range']
            if not (min_val <= value <= max_val):
                errors.append(f'Value must be between {min_val} and {max_val}')
    
    return {
        'valid': len(errors) == 0,
        'errors': errors
    }

def sanitize_string(input_string, max_length=None, allow_html=False):
    """Sanitize string input"""
    if not input_string:
        return ""
    
    # Convert to string and strip whitespace
    sanitized = str(input_string).strip()
    
    # Remove HTML tags if not allowed
    if not allow_html:
        sanitized = re.sub(r'<[^>]+>', '', sanitized)
    
    # Limit length
    if max_length and len(sanitized) > max_length:
        sanitized = sanitized[:max_length]
    
    return sanitized

def validate_json_data(data, required_fields=None, optional_fields=None):
    """Validate JSON data structure"""
    errors = []
    
    if not isinstance(data, dict):
        return {'valid': False, 'errors': ['Data must be a JSON object']}
    
    # Check required fields
    if required_fields:
        for field in required_fields:
            if field not in data or data[field] is None:
                errors.append(f'Required field missing: {field}')
    
    # Check for unexpected fields
    if required_fields or optional_fields:
        allowed_fields = set()
        if required_fields:
            allowed_fields.update(required_fields)
        if optional_fields:
            allowed_fields.update(optional_fields)
        
        for field in data.keys():
            if field not in allowed_fields:
                errors.append(f'Unexpected field: {field}')
    
    return {
        'valid': len(errors) == 0,
        'errors': errors
    }
