"""
NHS Number Validation Utilities
Implements NHS Digital standards for NHS Number validation
"""

import re
from typing import Tuple, Optional

class NHSNumberValidator:
    """Validates NHS Numbers according to NHS Digital specifications"""
    
    @staticmethod
    def validate_format(nhs_number: str) -> Tuple[bool, str]:
        """Validate NHS number format"""
        # Remove spaces and hyphens
        clean_number = re.sub(r'[\s-]', '', nhs_number)
        
        # Check length
        if len(clean_number) != 10:
            return False, f"NHS number must be 10 digits, got {len(clean_number)}"
        
        # Check all digits
        if not clean_number.isdigit():
            return False, "NHS number must contain only digits"
        
        return True, clean_number
    
    @staticmethod
    def validate_check_digit(nhs_number: str) -> Tuple[bool, str]:
        """Validate NHS number check digit using Modulus 11 algorithm"""
        is_valid, clean_number = NHSNumberValidator.validate_format(nhs_number)
        if not is_valid:
            return False, clean_number
        
        # Extract first 9 digits and check digit
        digits = [int(d) for d in clean_number[:9]]
        check_digit = int(clean_number[9])
        
        # Calculate expected check digit
        total = sum(digit * (10 - i) for i, digit in enumerate(digits))
        remainder = total % 11
        expected_check = 11 - remainder
        
        # Handle special cases
        if expected_check == 11:
            expected_check = 0
        elif expected_check == 10:
            return False, "Invalid NHS number - check digit cannot be 10"
        
        if check_digit != expected_check:
            return False, f"Invalid check digit. Expected {expected_check}, got {check_digit}"
        
        return True, clean_number
    
    @staticmethod
    def format_nhs_number(nhs_number: str) -> Optional[str]:
        """Format NHS number with standard spacing (XXX XXX XXXX)"""
        is_valid, clean_number = NHSNumberValidator.validate_check_digit(nhs_number)
        if not is_valid:
            return None
        
        return f"{clean_number[:3]} {clean_number[3:6]} {clean_number[6:]}"
    
    @staticmethod
    def is_valid(nhs_number: str) -> bool:
        """Check if NHS number is valid"""
        is_valid, _ = NHSNumberValidator.validate_check_digit(nhs_number)
        return is_valid
