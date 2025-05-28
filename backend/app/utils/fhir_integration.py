"""
FHIR Integration for NHS Interoperability
Handles bi-directional data sharing with NHS systems
"""

import json
import requests
from datetime import datetime, date
from flask import current_app
from typing import Dict, Any, Optional, List

class FHIRClient:
    """FHIR client for NHS integration"""
    
    def __init__(self):
        self.base_url = current_app.config.get('FHIR_BASE_URL')
        self.api_key = current_app.config.get('FHIR_API_KEY')
        self.headers = {
            'Content-Type': 'application/fhir+json',
            'Accept': 'application/fhir+json',
            'Authorization': f'Bearer {self.api_key}' if self.api_key else None
        }
    
    def create_patient_resource(self, user, patient_profile) -> Dict[str, Any]:
        """Create FHIR Patient resource"""
        
        # Build patient identifier
        identifiers = []
        if user.nhs_number:
            identifiers.append({
                "use": "official",
                "system": "https://fhir.nhs.uk/Id/nhs-number",
                "value": user.nhs_number
            })
        
        # Build patient name
        name = [{
            "use": "official",
            "family": user.last_name,
            "given": [user.first_name]
        }]
        
        # Build contact information
        telecom = []
        if user.email:
            telecom.append({
                "system": "email",
                "value": user.email,
                "use": "home"
            })
        
        if user.phone:
            telecom.append({
                "system": "phone",
                "value": user.phone,
                "use": "home"
            })
        
        # Build patient resource
        patient_resource = {
            "resourceType": "Patient",
            "identifier": identifiers,
            "active": user.is_active,
            "name": name,
            "telecom": telecom
        }
        
        # Add birth date if available
        if patient_profile and patient_profile.date_of_birth:
            patient_resource["birthDate"] = patient_profile.date_of_birth.isoformat()
        
        # Add gender if available
        if patient_profile and patient_profile.gender:
            # Map to FHIR gender codes
            gender_map = {
                'male': 'male',
                'female': 'female',
                'other': 'other',
                'unknown': 'unknown'
            }
            fhir_gender = gender_map.get(patient_profile.gender.lower(), 'unknown')
            patient_resource["gender"] = fhir_gender
        
        # Add GP practice if available
        if user.gp_practice_code:
            patient_resource["generalPractitioner"] = [{
                "reference": f"Organization/{user.gp_practice_code}",
                "display": "GP Practice"
            }]
        
        # Add emergency contact if available
        if patient_profile and patient_profile.emergency_contact_name:
            contact = {
                "relationship": [{
                    "coding": [{
                        "system": "http://terminology.hl7.org/CodeSystem/v2-0131",
                        "code": "EP",
                        "display": "Emergency contact person"
                    }]
                }],
                "name": {
                    "text": patient_profile.emergency_contact_name
                }
            }
            
            if patient_profile.emergency_contact_phone:
                contact["telecom"] = [{
                    "system": "phone",
                    "value": patient_profile.emergency_contact_phone,
                    "use": "home"
                }]
            
            patient_resource["contact"] = [contact]
        
        return patient_resource
    
    def create_observation_resource(self, health_record, patient_fhir_id) -> Dict[str, Any]:
        """Create FHIR Observation resource from health record"""
        
        # Map record types to LOINC codes
        loinc_mapping = {
            'blood_pressure': {
                'systolic': '8480-6',
                'diastolic': '8462-4',
                'panel': '85354-9'
            },
            'heart_rate': '8867-4',
            'glucose': '33747-0',
            'weight': '29463-7',
            'temperature': '8310-5',
            'oxygen_saturation': '2708-6'
        }
        
        observation = {
            "resourceType": "Observation",
            "status": "final",
            "subject": {
                "reference": f"Patient/{patient_fhir_id}"
            },
            "effectiveDateTime": health_record.timestamp.isoformat(),
            "issued": health_record.created_at.isoformat()
        }
        
        # Handle different types of observations
        if health_record.record_type == 'blood_pressure':
            observation.update({
                "category": [{
                    "coding": [{
                        "system": "http://terminology.hl7.org/CodeSystem/observation-category",
                        "code": "vital-signs",
                        "display": "Vital Signs"
                    }]
                }],
                "code": {
                    "coding": [{
                        "system": "http://loinc.org",
                        "code": loinc_mapping['blood_pressure']['panel'],
                        "display": "Blood pressure"
                    }]
                },
                "component": [
                    {
                        "code": {
                            "coding": [{
                                "system": "http://loinc.org",
                                "code": loinc_mapping['blood_pressure']['systolic'],
                                "display": "Systolic blood pressure"
                            }]
                        },
                        "valueQuantity": {
                            "value": health_record.value.get('systolic'),
                            "unit": health_record.unit or "mmHg",
                            "system": "http://unitsofmeasure.org",
                            "code": "mm[Hg]"
                        }
                    },
                    {
                        "code": {
                            "coding": [{
                                "system": "http://loinc.org",
                                "code": loinc_mapping['blood_pressure']['diastolic'],
                                "display": "Diastolic blood pressure"
                            }]
                        },
                        "valueQuantity": {
                            "value": health_record.value.get('diastolic'),
                            "unit": health_record.unit or "mmHg",
                            "system": "http://unitsofmeasure.org",
                            "code": "mm[Hg]"
                        }
                    }
                ]
            })
        else:
            # Simple observation
            loinc_code = loinc_mapping.get(health_record.record_type)
            if loinc_code:
                observation.update({
                    "category": [{
                        "coding": [{
                            "system": "http://terminology.hl7.org/CodeSystem/observation-category",
                            "code": "vital-signs",
                            "display": "Vital Signs"
                        }]
                    }],
                    "code": {
                        "coding": [{
                            "system": "http://loinc.org",
                            "code": loinc_code,
                            "display": health_record.record_type.replace('_', ' ').title()
                        }]
                    },
                    "valueQuantity": {
                        "value": health_record.value,
                        "unit": health_record.unit,
                        "system": "http://unitsofmeasure.org"
                    }
                })
        
        # Add device information if available
        if health_record.device:
            observation["device"] = {
                "display": f"{health_record.device.manufacturer} {health_record.device.model}".strip()
            }
        
        # Add notes if available
        if health_record.notes:
            observation["note"] = [{
                "text": health_record.notes
            }]
        
        return observation
    
    def send_to_fhir_server(self, resource: Dict[str, Any]) -> Optional[str]:
        """Send resource to FHIR server"""
        try:
            resource_type = resource.get('resourceType')
            if not resource_type:
                raise ValueError("Resource must have resourceType")
            
            url = f"{self.base_url}/{resource_type}"
            
            response = requests.post(
                url,
                json=resource,
                headers=self.headers,
                timeout=30
            )
            
            if response.status_code in [200, 201]:
                result = response.json()
                return result.get('id')
            else:
                current_app.logger.error(f"FHIR server error: {response.status_code} - {response.text}")
                return None
                
        except requests.exceptions.RequestException as e:
            current_app.logger.error(f"FHIR request error: {str(e)}")
            return None
        except Exception as e:
            current_app.logger.error(f"FHIR send error: {str(e)}")
            return None
    
    def get_from_fhir_server(self, resource_type: str, resource_id: str) -> Optional[Dict[str, Any]]:
        """Get resource from FHIR server"""
        try:
            url = f"{self.base_url}/{resource_type}/{resource_id}"
            
            response = requests.get(
                url,
                headers=self.headers,
                timeout=30
            )
            
            if response.status_code == 200:
                return response.json()
            else:
                current_app.logger.error(f"FHIR get error: {response.status_code} - {response.text}")
                return None
                
        except requests.exceptions.RequestException as e:
            current_app.logger.error(f"FHIR request error: {str(e)}")
            return None
        except Exception as e:
            current_app.logger.error(f"FHIR get error: {str(e)}")
            return None

# Helper functions for easy integration
def create_fhir_patient(user, patient_profile) -> Optional[str]:
    """Create FHIR patient and return FHIR ID"""
    try:
        client = FHIRClient()
        patient_resource = client.create_patient_resource(user, patient_profile)
        return client.send_to_fhir_server(patient_resource)
    except Exception as e:
        current_app.logger.error(f"Failed to create FHIR patient: {str(e)}")
        return None

def update_fhir_patient(user, patient_profile, fhir_id: str = None) -> bool:
    """Update FHIR patient resource"""
    try:
        client = FHIRClient()
        patient_resource = client.create_patient_resource(user, patient_profile)
        
        if fhir_id:
            patient_resource['id'] = fhir_id
            # For updates, you would typically use PUT request
            # This is a simplified implementation
        
        result = client.send_to_fhir_server(patient_resource)
        return result is not None
    except Exception as e:
        current_app.logger.error(f"Failed to update FHIR patient: {str(e)}")
        return False

def send_health_record_to_fhir(health_record, patient_fhir_id: str) -> Optional[str]:
    """Send health record as FHIR Observation"""
    try:
        client = FHIRClient()
        observation_resource = client.create_observation_resource(health_record, patient_fhir_id)
        return client.send_to_fhir_server(observation_resource)
    except Exception as e:
        current_app.logger.error(f"Failed to send health record to FHIR: {str(e)}")
        return None

def validate_fhir_resource(resource: Dict[str, Any]) -> Dict[str, Any]:
    """Basic FHIR resource validation"""
    errors = []
    
    if not isinstance(resource, dict):
        errors.append("Resource must be a JSON object")
        return {'valid': False, 'errors': errors}
    
    if 'resourceType' not in resource:
        errors.append("Resource must have resourceType")
    
    # Add more validation based on FHIR specification
    valid_resource_types = [
        'Patient', 'Observation', 'Device', 'Practitioner',
        'Organization', 'Encounter', 'DiagnosticReport'
    ]
    
    if resource.get('resourceType') not in valid_resource_types:
        errors.append(f"Invalid resourceType: {resource.get('resourceType')}")
    
    return {
        'valid': len(errors) == 0,
        'errors': errors
    }
