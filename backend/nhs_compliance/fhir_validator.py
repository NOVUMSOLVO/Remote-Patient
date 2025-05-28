"""
FHIR R4 Validation for NHS Digital Compliance
Validates FHIR resources against UK Core profiles
"""

import json
import re
from datetime import datetime

class FHIRValidator:
    def __init__(self, config):
        self.config = config
        
    def validate_nhs_number(self, nhs_number):
        """Validate NHS number format and check digit"""
        if not re.match(r'^\d{10}$', nhs_number):
            return False
            
        # Calculate check digit using Modulus 11
        digits = [int(d) for d in nhs_number[:9]]
        check_sum = sum(digit * (10 - i) for i, digit in enumerate(digits))
        check_digit = (11 - (check_sum % 11)) % 11
        
        if check_digit == 10:
            return False  # Invalid NHS number
            
        return int(nhs_number[9]) == check_digit
    
    def validate_patient_resource(self, patient):
        """Validate Patient FHIR resource"""
        required_fields = self.config['Patient']['required_fields']
        
        for field in required_fields:
            if field not in patient:
                return False, f"Missing required field: {field}"
        
        # Validate NHS number if present
        for identifier in patient.get('identifier', []):
            if identifier.get('system') == 'https://fhir.nhs.uk/Id/nhs-number':
                nhs_number = identifier.get('value')
                if not self.validate_nhs_number(nhs_number):
                    return False, f"Invalid NHS number: {nhs_number}"
        
        return True, "Valid"
    
    def validate_observation_resource(self, observation):
        """Validate Observation FHIR resource"""
        required_fields = self.config['Observation']['required_fields']
        
        for field in required_fields:
            if field not in observation:
                return False, f"Missing required field: {field}"
        
        # Validate status
        valid_statuses = ['registered', 'preliminary', 'final', 'amended', 'corrected', 'cancelled']
        if observation.get('status') not in valid_statuses:
            return False, f"Invalid status: {observation.get('status')}"
        
        return True, "Valid"
