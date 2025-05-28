"""
NHS Personal Demographics Service (PDS) Integration
Implements secure patient demographic data retrieval
"""

import requests
import json
from datetime import datetime
import logging

class PDSClient:
    def __init__(self, config):
        self.config = config
        self.base_url = config['base_url']
        self.access_token = None
        
    def authenticate(self, client_id, client_secret):
        """Authenticate with NHS Digital OAuth2"""
        token_url = self.config['authentication']['token_endpoint']
        
        data = {
            'grant_type': 'client_credentials',
            'client_id': client_id,
            'client_secret': client_secret,
            'scope': ' '.join(self.config['authentication']['scopes'])
        }
        
        response = requests.post(token_url, data=data)
        if response.status_code == 200:
            token_data = response.json()
            self.access_token = token_data['access_token']
            return True
        return False
    
    def search_patient(self, nhs_number):
        """Search for patient by NHS number"""
        if not self.access_token:
            raise ValueError("Not authenticated with PDS")
        
        url = f"{self.base_url}/Patient"
        headers = {
            'Authorization': f'Bearer {self.access_token}',
            'Accept': 'application/fhir+json',
            'X-Request-ID': str(uuid.uuid4())
        }
        
        params = {
            'identifier': f'https://fhir.nhs.uk/Id/nhs-number|{nhs_number}'
        }
        
        response = requests.get(url, headers=headers, params=params)
        return response.json() if response.status_code == 200 else None
