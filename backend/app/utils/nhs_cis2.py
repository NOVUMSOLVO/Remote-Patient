"""
NHS CIS2 (Care Identity Service 2) Authentication Integration
Implements NHS Digital authentication standards for healthcare applications
"""

import requests
import jwt
import json
from datetime import datetime, timedelta
from flask import current_app, session
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend
import base64
import secrets
import logging

logger = logging.getLogger(__name__)

class NHS_CIS2_Client:
    """NHS CIS2 Authentication Client"""
    
    def __init__(self):
        self.base_url = current_app.config.get('NHS_CIS2_BASE_URL', 'https://auth.login.nhs.uk')
        self.client_id = current_app.config.get('NHS_CIS2_CLIENT_ID')
        self.client_secret = current_app.config.get('NHS_CIS2_CLIENT_SECRET')
        self.redirect_uri = current_app.config.get('NHS_CIS2_REDIRECT_URI')
        self.scope = current_app.config.get('NHS_CIS2_SCOPE', 'openid profile smartcard')
        
    def generate_authorization_url(self, state=None):
        """Generate NHS CIS2 authorization URL"""
        if not state:
            state = secrets.token_urlsafe(32)
            
        # Store state in session for CSRF protection
        session['oauth_state'] = state
        
        params = {
            'response_type': 'code',
            'client_id': self.client_id,
            'redirect_uri': self.redirect_uri,
            'scope': self.scope,
            'state': state,
            'nonce': secrets.token_urlsafe(16)
        }
        
        query_string = '&'.join([f"{k}={v}" for k, v in params.items()])
        auth_url = f"{self.base_url}/auth?{query_string}"
        
        logger.info(f"Generated NHS CIS2 auth URL for client: {self.client_id}")
        return auth_url, state
    
    def exchange_code_for_token(self, authorization_code, state):
        """Exchange authorization code for access token"""
        # Verify state parameter
        if session.get('oauth_state') != state:
            raise ValueError("Invalid state parameter - possible CSRF attack")
        
        token_url = f"{self.base_url}/token"
        
        data = {
            'grant_type': 'authorization_code',
            'code': authorization_code,
            'redirect_uri': self.redirect_uri,
            'client_id': self.client_id,
            'client_secret': self.client_secret
        }
        
        headers = {
            'Content-Type': 'application/x-www-form-urlencoded',
            'Accept': 'application/json'
        }
        
        try:
            response = requests.post(token_url, data=data, headers=headers, timeout=30)
            response.raise_for_status()
            
            token_data = response.json()
            logger.info("Successfully exchanged code for NHS CIS2 token")
            return token_data
            
        except requests.exceptions.RequestException as e:
            logger.error(f"Failed to exchange code for token: {str(e)}")
            raise Exception(f"Token exchange failed: {str(e)}")
    
    def get_user_info(self, access_token):
        """Get user information from NHS CIS2"""
        userinfo_url = f"{self.base_url}/userinfo"
        
        headers = {
            'Authorization': f'Bearer {access_token}',
            'Accept': 'application/json'
        }
        
        try:
            response = requests.get(userinfo_url, headers=headers, timeout=30)
            response.raise_for_status()
            
            user_info = response.json()
            logger.info(f"Retrieved user info for NHS ID: {user_info.get('sub')}")
            return user_info
            
        except requests.exceptions.RequestException as e:
            logger.error(f"Failed to get user info: {str(e)}")
            raise Exception(f"User info retrieval failed: {str(e)}")
    
    def validate_jwt_token(self, jwt_token):
        """Validate JWT token from NHS CIS2"""
        try:
            # Get public keys from NHS CIS2 JWKS endpoint
            jwks_url = f"{self.base_url}/.well-known/jwks.json"
            jwks_response = requests.get(jwks_url, timeout=30)
            jwks_response.raise_for_status()
            jwks = jwks_response.json()
            
            # Decode and validate JWT
            header = jwt.get_unverified_header(jwt_token)
            key_id = header.get('kid')
            
            # Find the correct public key
            public_key = None
            for key in jwks['keys']:
                if key['kid'] == key_id:
                    public_key = jwt.algorithms.RSAAlgorithm.from_jwk(json.dumps(key))
                    break
            
            if not public_key:
                raise ValueError("Public key not found")
            
            # Validate the token
            payload = jwt.decode(
                jwt_token,
                public_key,
                algorithms=['RS256'],
                audience=self.client_id,
                issuer=self.base_url
            )
            
            logger.info(f"Successfully validated JWT for user: {payload.get('sub')}")
            return payload
            
        except Exception as e:
            logger.error(f"JWT validation failed: {str(e)}")
            raise Exception(f"JWT validation failed: {str(e)}")
    
    def refresh_token(self, refresh_token):
        """Refresh access token"""
        token_url = f"{self.base_url}/token"
        
        data = {
            'grant_type': 'refresh_token',
            'refresh_token': refresh_token,
            'client_id': self.client_id,
            'client_secret': self.client_secret
        }
        
        headers = {
            'Content-Type': 'application/x-www-form-urlencoded',
            'Accept': 'application/json'
        }
        
        try:
            response = requests.post(token_url, data=data, headers=headers, timeout=30)
            response.raise_for_status()
            
            token_data = response.json()
            logger.info("Successfully refreshed NHS CIS2 token")
            return token_data
            
        except requests.exceptions.RequestException as e:
            logger.error(f"Failed to refresh token: {str(e)}")
            raise Exception(f"Token refresh failed: {str(e)}")

class NHS_Smartcard_Validator:
    """NHS Smartcard validation utilities"""
    
    @staticmethod
    def validate_smartcard_data(smartcard_data):
        """Validate NHS smartcard data"""
        required_fields = [
            'certificate',
            'role_profile',
            'organisation_code',
            'user_id'
        ]
        
        for field in required_fields:
            if field not in smartcard_data:
                raise ValueError(f"Missing required smartcard field: {field}")
        
        # Validate organisation code format
        org_code = smartcard_data.get('organisation_code')
        if not org_code or len(org_code) != 3:
            raise ValueError("Invalid NHS organisation code")
        
        # Validate role profile
        role_profile = smartcard_data.get('role_profile')
        valid_roles = [
            'S8000:G8000:R8000',  # Doctor
            'S8001:G8001:R8001',  # Nurse
            'S8002:G8002:R8002',  # Admin
            'S8003:G8003:R8003'   # Healthcare Assistant
        ]
        
        if role_profile not in valid_roles:
            logger.warning(f"Unknown role profile: {role_profile}")
        
        return True
    
    @staticmethod
    def extract_user_role(role_profile):
        """Extract user role from NHS role profile"""
        role_mapping = {
            'S8000:G8000:R8000': 'doctor',
            'S8001:G8001:R8001': 'nurse',
            'S8002:G8002:R8002': 'admin',
            'S8003:G8003:R8003': 'healthcare_assistant'
        }
        
        return role_mapping.get(role_profile, 'user')

class NHS_Data_Standards:
    """NHS data standards and validation utilities"""
    
    @staticmethod
    def validate_nhs_number(nhs_number):
        """Validate NHS number using Modulus 11 algorithm"""
        if not nhs_number or len(nhs_number) != 10:
            return False
        
        if not nhs_number.isdigit():
            return False
        
        # Calculate check digit using Modulus 11
        total = 0
        for i, digit in enumerate(nhs_number[:9]):
            total += int(digit) * (10 - i)
        
        remainder = total % 11
        check_digit = 11 - remainder
        
        if check_digit == 11:
            check_digit = 0
        elif check_digit == 10:
            return False  # Invalid NHS number
        
        return int(nhs_number[9]) == check_digit
    
    @staticmethod
    def validate_organisation_code(org_code):
        """Validate NHS organisation code"""
        if not org_code or len(org_code) != 3:
            return False
        
        # NHS organisation codes are 3-character alphanumeric
        return org_code.isalnum()
    
    @staticmethod
    def format_nhs_number(nhs_number):
        """Format NHS number with spaces for display"""
        if len(nhs_number) == 10:
            return f"{nhs_number[:3]} {nhs_number[3:6]} {nhs_number[6:]}"
        return nhs_number

def create_nhs_cis2_client():
    """Factory function to create NHS CIS2 client"""
    return NHS_CIS2_Client()

def validate_nhs_authentication(token_data):
    """Validate NHS authentication response"""
    try:
        client = create_nhs_cis2_client()
        
        # Validate ID token if present
        if 'id_token' in token_data:
            payload = client.validate_jwt_token(token_data['id_token'])
            
            # Additional NHS-specific validations
            if 'smartcard' in payload:
                NHS_Smartcard_Validator.validate_smartcard_data(payload['smartcard'])
            
            return payload
        
        return None
        
    except Exception as e:
        logger.error(f"NHS authentication validation failed: {str(e)}")
        raise
