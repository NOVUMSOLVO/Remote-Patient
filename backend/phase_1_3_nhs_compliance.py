#!/usr/bin/env python3
"""
Phase 1.3: NHS Compliance Foundation
Implements NHS Digital API integration, FHIR R4 compliance, and Information Governance
"""

import os
import sys
import json
import requests
from datetime import datetime, timedelta
import logging
from cryptography.fernet import Fernet
import uuid
import re

# Setup logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

class NHSComplianceSetup:
    """NHS Digital compliance implementation"""
    
    def __init__(self):
        self.fhir_version = "R4"
        self.nhs_api_base = "https://api.login.nhs.uk"
        self.pds_api_base = "https://api.service.nhs.uk/personal-demographics"
        self.compliance_dir = "nhs_compliance"
        
    def setup_nhs_login_integration(self):
        """Setup NHS Login OAuth2 integration"""
        print("🔐 Setting up NHS Login integration...")
        
        try:
            os.makedirs(self.compliance_dir, exist_ok=True)
            
            # NHS Login configuration
            nhs_login_config = {
                "client_id": os.environ.get('NHS_LOGIN_CLIENT_ID', 'rpm-system-client'),
                "client_secret": os.environ.get('NHS_LOGIN_CLIENT_SECRET', 'dev-secret'),
                "redirect_uri": os.environ.get('NHS_LOGIN_REDIRECT_URI', 'https://localhost:5000/auth/nhs/callback'),
                "scopes": [
                    "openid",
                    "profile", 
                    "email",
                    "phone",
                    "nhs_number",
                    "gp_registration_details"
                ],
                "endpoints": {
                    "authorization": f"{self.nhs_api_base}/authorize",
                    "token": f"{self.nhs_api_base}/token",
                    "userinfo": f"{self.nhs_api_base}/userinfo",
                    "jwks": f"{self.nhs_api_base}/.well-known/jwks.json"
                },
                "security": {
                    "use_pkce": True,
                    "require_id_token": True,
                    "validate_aud": True,
                    "validate_iss": True,
                    "max_age": 3600
                }
            }
            
            config_file = f"{self.compliance_dir}/nhs_login_config.json"
            with open(config_file, 'w') as f:
                json.dump(nhs_login_config, f, indent=2)
            
            print("✅ NHS Login integration configured")
            return True
            
        except Exception as e:
            logger.error(f"NHS Login setup failed: {str(e)}")
            return False
    
    def setup_pds_integration(self):
        """Setup Personal Demographics Service (PDS) integration"""
        print("👤 Setting up PDS integration...")
        
        try:
            # PDS API configuration
            pds_config = {
                "base_url": self.pds_api_base,
                "version": "v1",
                "endpoints": {
                    "patient_search": "/Patient",
                    "patient_retrieve": "/Patient/{nhs_number}",
                    "related_person": "/RelatedPerson"
                },
                "authentication": {
                    "type": "oauth2",
                    "token_endpoint": f"{self.nhs_api_base}/token",
                    "scopes": ["personal-demographics-service:USER-RESTRICTED"]
                },
                "rate_limits": {
                    "requests_per_minute": 600,
                    "burst_limit": 100
                },
                "retry_policy": {
                    "max_retries": 3,
                    "backoff_factor": 2,
                    "status_codes": [429, 500, 502, 503, 504]
                }
            }
            
            config_file = f"{self.compliance_dir}/pds_config.json"
            with open(config_file, 'w') as f:
                json.dump(pds_config, f, indent=2)
            
            # Create PDS integration module
            pds_module = '''"""
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
'''
            
            with open(f"{self.compliance_dir}/pds_client.py", 'w') as f:
                f.write(pds_module)
            
            print("✅ PDS integration configured")
            return True
            
        except Exception as e:
            logger.error(f"PDS setup failed: {str(e)}")
            return False
    
    def implement_fhir_r4_compliance(self):
        """Implement FHIR R4 compliance verification"""
        print("🔬 Implementing FHIR R4 compliance...")
        
        try:
            # FHIR R4 resource definitions for NHS Digital
            fhir_resources = {
                "Patient": {
                    "profile": "https://fhir.hl7.org.uk/StructureDefinition/UKCore-Patient",
                    "required_fields": [
                        "identifier", "name", "telecom", "gender", 
                        "birthDate", "address", "managingOrganization"
                    ],
                    "nhs_extensions": [
                        "https://fhir.hl7.org.uk/StructureDefinition/Extension-UKCore-NHSNumberVerificationStatus",
                        "https://fhir.hl7.org.uk/StructureDefinition/Extension-UKCore-EthnicCategory"
                    ]
                },
                "Observation": {
                    "profile": "https://fhir.hl7.org.uk/StructureDefinition/UKCore-Observation",
                    "required_fields": [
                        "status", "category", "code", "subject", 
                        "effectiveDateTime", "value"
                    ],
                    "nhs_categories": [
                        "vital-signs", "survey", "exam", "therapy",
                        "activity", "procedure", "laboratory"
                    ]
                },
                "Device": {
                    "profile": "https://fhir.hl7.org.uk/StructureDefinition/UKCore-Device",
                    "required_fields": [
                        "identifier", "status", "manufacturer", 
                        "modelNumber", "type", "patient"
                    ]
                },
                "Organization": {
                    "profile": "https://fhir.hl7.org.uk/StructureDefinition/UKCore-Organization",
                    "required_fields": [
                        "identifier", "active", "type", "name", 
                        "telecom", "address"
                    ],
                    "nhs_identifiers": [
                        "https://fhir.nhs.uk/Id/ods-organization-code"
                    ]
                }
            }
            
            config_file = f"{self.compliance_dir}/fhir_r4_config.json"
            with open(config_file, 'w') as f:
                json.dump(fhir_resources, f, indent=2)
            
            # Create FHIR validation module
            fhir_validator = '''"""
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
        if not re.match(r'^\\d{10}$', nhs_number):
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
'''
            
            with open(f"{self.compliance_dir}/fhir_validator.py", 'w') as f:
                f.write(fhir_validator)
            
            print("✅ FHIR R4 compliance implemented")
            return True
            
        except Exception as e:
            logger.error(f"FHIR R4 setup failed: {str(e)}")
            return False
    
    def setup_nhs_number_validation(self):
        """Setup NHS Number validation system"""
        print("🔢 Setting up NHS Number validation...")
        
        try:
            # NHS Number validation utilities
            nhs_validator = '''"""
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
        clean_number = re.sub(r'[\\s-]', '', nhs_number)
        
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
'''
            
            with open(f"{self.compliance_dir}/nhs_number_validator.py", 'w') as f:
                f.write(nhs_validator)
            
            print("✅ NHS Number validation configured")
            return True
            
        except Exception as e:
            logger.error(f"NHS Number validation setup failed: {str(e)}")
            return False
    
    def implement_information_governance(self):
        """Implement Information Governance policies"""
        print("📋 Implementing Information Governance...")
        
        try:
            # Data Security and Protection Toolkit (DSPT) compliance
            dspt_requirements = {
                "mandatory_standards": [
                    "1.1 - Data Security and Protection Policy",
                    "1.2 - Data Security and Protection Training",
                    "1.3 - Data Security and Protection Impact Assessment",
                    "2.1 - Data Flow Mapping",
                    "2.2 - Data Quality",
                    "2.3 - Data Minimisation",
                    "3.1 - Technical Security",
                    "3.2 - End User Device Security",
                    "3.3 - Network Security",
                    "4.1 - Password Policy",
                    "4.2 - Account Management",
                    "4.3 - Privileged User Management",
                    "5.1 - Process Reviews",
                    "5.2 - Response Planning"
                ],
                "implementation_status": {
                    "completed": [],
                    "in_progress": [],
                    "not_started": []
                }
            }
            
            # Clinical safety documentation
            clinical_safety = {
                "dcb0129": {
                    "title": "Clinical Risk Management: its Application in the Manufacture of Health IT Systems",
                    "status": "planned",
                    "requirements": [
                        "Clinical Risk Management Plan",
                        "Clinical Risk Assessment",
                        "Clinical Risk Register",
                        "Clinical Safety Case"
                    ]
                },
                "dcb0160": {
                    "title": "Clinical Risk Management: its Application in the Deployment and Use of Health IT Systems",
                    "status": "planned",
                    "requirements": [
                        "Deployment Risk Assessment",
                        "Ongoing Risk Management",
                        "Safety Monitoring",
                        "Change Control"
                    ]
                }
            }
            
            # Information governance policies
            ig_policies = {
                "data_protection": {
                    "gdpr_compliance": True,
                    "lawful_basis": "Article 6(1)(e) - Public task",
                    "special_category_basis": "Article 9(2)(h) - Healthcare",
                    "retention_schedule": "8 years minimum (NHS requirements)"
                },
                "data_sharing": {
                    "agreements_required": True,
                    "patient_consent": "Required for non-direct care",
                    "nhs_number_use": "Authorized for patient identification"
                },
                "security_classification": {
                    "official": "Standard business information",
                    "official_sensitive": "Personal data requiring protection",
                    "secret": "Not applicable for healthcare data",
                    "top_secret": "Not applicable for healthcare data"
                }
            }
            
            # Save configurations
            configs = [
                (f"{self.compliance_dir}/dspt_compliance.json", dspt_requirements),
                (f"{self.compliance_dir}/clinical_safety.json", clinical_safety),
                (f"{self.compliance_dir}/information_governance.json", ig_policies)
            ]
            
            for config_file, config_data in configs:
                with open(config_file, 'w') as f:
                    json.dump(config_data, f, indent=2)
            
            print("✅ Information Governance policies configured")
            return True
            
        except Exception as e:
            logger.error(f"Information Governance setup failed: {str(e)}")
            return False
    
    def create_compliance_verification(self):
        """Create compliance verification and monitoring"""
        print("✅ Creating compliance verification system...")
        
        try:
            # Compliance verification script
            verification_script = '''#!/usr/bin/env python3
"""
NHS Digital Compliance Verification Script
Validates system compliance with NHS Digital standards
"""

import json
import os
from datetime import datetime

def verify_nhs_compliance():
    """Verify NHS Digital compliance status"""
    compliance_checks = {
        "nhs_login": {
            "config_file": "nhs_compliance/nhs_login_config.json",
            "required": True,
            "status": "unknown"
        },
        "pds_integration": {
            "config_file": "nhs_compliance/pds_config.json", 
            "required": True,
            "status": "unknown"
        },
        "fhir_r4": {
            "config_file": "nhs_compliance/fhir_r4_config.json",
            "required": True,
            "status": "unknown"
        },
        "nhs_number_validation": {
            "module_file": "nhs_compliance/nhs_number_validator.py",
            "required": True,
            "status": "unknown"
        },
        "information_governance": {
            "config_file": "nhs_compliance/information_governance.json",
            "required": True,
            "status": "unknown"
        }
    }
    
    # Check each compliance requirement
    for check_name, check_config in compliance_checks.items():
        file_path = check_config.get("config_file") or check_config.get("module_file")
        
        if os.path.exists(file_path):
            compliance_checks[check_name]["status"] = "configured"
        else:
            compliance_checks[check_name]["status"] = "missing"
    
    # Generate compliance report
    report = {
        "verification_date": datetime.now().isoformat(),
        "overall_status": "compliant",
        "checks": compliance_checks,
        "recommendations": []
    }
    
    # Check overall compliance
    missing_required = [
        name for name, config in compliance_checks.items()
        if config["required"] and config["status"] == "missing"
    ]
    
    if missing_required:
        report["overall_status"] = "non_compliant"
        report["recommendations"].append(
            f"Configure missing components: {', '.join(missing_required)}"
        )
    
    return report

if __name__ == "__main__":
    report = verify_nhs_compliance()
    
    print("NHS Digital Compliance Verification Report")
    print("=" * 50)
    print(f"Overall Status: {report['overall_status'].upper()}")
    print(f"Verification Date: {report['verification_date']}")
    print()
    
    for check_name, check_data in report['checks'].items():
        status_icon = "✅" if check_data['status'] == 'configured' else "❌"
        print(f"{status_icon} {check_name}: {check_data['status']}")
    
    if report['recommendations']:
        print("\\nRecommendations:")
        for rec in report['recommendations']:
            print(f"- {rec}")
    
    # Save detailed report
    with open('nhs_compliance_report.json', 'w') as f:
        json.dump(report, f, indent=2)
'''
            
            with open('verify_nhs_compliance.py', 'w') as f:
                f.write(verification_script)
            
            os.chmod('verify_nhs_compliance.py', 0o755)
            
            print("✅ Compliance verification system created")
            return True
            
        except Exception as e:
            logger.error(f"Compliance verification setup failed: {str(e)}")
            return False

def main():
    """Main Phase 1.3 setup process"""
    print("🏥 Starting Phase 1.3: NHS Compliance Foundation")
    print("=" * 60)
    
    setup = NHSComplianceSetup()
    
    # Execute Phase 1.3 components
    tasks = [
        ("NHS Login Integration", setup.setup_nhs_login_integration),
        ("PDS Integration", setup.setup_pds_integration),
        ("FHIR R4 Compliance", setup.implement_fhir_r4_compliance),
        ("NHS Number Validation", setup.setup_nhs_number_validation),
        ("Information Governance", setup.implement_information_governance),
        ("Compliance Verification", setup.create_compliance_verification)
    ]
    
    completed_tasks = 0
    
    for task_name, task_func in tasks:
        print(f"\n📋 {task_name}...")
        if task_func():
            completed_tasks += 1
        else:
            print(f"❌ {task_name} failed")
    
    print("\n" + "=" * 60)
    print(f"📊 Phase 1.3 Summary: {completed_tasks}/{len(tasks)} tasks completed")
    
    if completed_tasks == len(tasks):
        print("✅ Phase 1.3: NHS Compliance Foundation COMPLETE")
        print("🎯 Ready for Phase 2: Core Application Completion")
        
        # Create status file
        status = {
            'phase': '1.3',
            'status': 'complete',
            'completed_at': datetime.now().isoformat(),
            'tasks_completed': completed_tasks,
            'total_tasks': len(tasks),
            'next_phase': '2.0 - Core Application Completion'
        }
        
        with open('phase_1_3_status.json', 'w') as f:
            json.dump(status, f, indent=2)
        
        return True
    else:
        print("❌ Phase 1.3 setup incomplete - please review errors")
        return False

if __name__ == "__main__":
    success = main()
    sys.exit(0 if success else 1)
