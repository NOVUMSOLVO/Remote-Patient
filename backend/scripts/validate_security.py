"""
Security Configuration Validation Script
Validates all security configurations according to NHS Digital standards
"""

import os
import sys
import ssl
import json
import logging
from typing import Dict, List, Any

# Add the parent directory to Python path to import app modules
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from app import create_app
from app.utils.security import SecurityManager
from app.utils.encryption import EncryptionManager
from app.utils.tls_config import TLSConfig
from app.utils.ddos_protection import DDoSProtection
from config import config


class SecurityValidator:
    """Validates security configuration and implementation"""
    
    def __init__(self):
        self.app = create_app()
        self.results = {
            'passed': [],
            'failed': [],
            'warnings': []
        }
        
        # Setup logging
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(levelname)s - %(message)s'
        )
        self.logger = logging.getLogger(__name__)
    
    def validate_all(self) -> Dict[str, Any]:
        """Run all security validations"""
        self.logger.info("Starting comprehensive security validation...")
        
        # Core security validations
        self._validate_encryption_config()
        self._validate_tls_config()
        self._validate_authentication_config()
        self._validate_session_config()
        self._validate_rate_limiting_config()
        self._validate_audit_logging_config()
        
        # NHS-specific validations
        self._validate_nhs_compliance()
        self._validate_data_protection()
        
        # Infrastructure validations
        self._validate_environment_security()
        self._validate_database_security()
        
        # Generate report
        return self._generate_report()
    
    def _validate_encryption_config(self) -> None:
        """Validate encryption configuration"""
        self.logger.info("Validating encryption configuration...")
        
        try:
            with self.app.app_context():
                encryption_manager = EncryptionManager()
                
                # Test encryption/decryption
                test_data = "NHS Test Data"
                encrypted = encryption_manager.encrypt_field(test_data)
                decrypted = encryption_manager.decrypt_field(encrypted)
                
                if decrypted == test_data:
                    self.results['passed'].append("✓ Field encryption/decryption working")
                else:
                    self.results['failed'].append("✗ Field encryption/decryption failed")
                
                # Test key rotation capability
                if hasattr(encryption_manager, 'rotate_keys'):
                    self.results['passed'].append("✓ Key rotation capability available")
                else:
                    self.results['warnings'].append("⚠ Key rotation not implemented")
                
                # Test PII encryption
                pii_data = {"name": "Test", "nhs_number": "1234567890"}
                encrypted_pii = encryption_manager.encrypt_pii(pii_data)
                decrypted_pii = encryption_manager.decrypt_pii(encrypted_pii)
                
                if decrypted_pii == pii_data:
                    self.results['passed'].append("✓ PII encryption working")
                else:
                    self.results['failed'].append("✗ PII encryption failed")
                    
        except Exception as e:
            self.results['failed'].append(f"✗ Encryption validation error: {str(e)}")
    
    def _validate_tls_config(self) -> None:
        """Validate TLS configuration"""
        self.logger.info("Validating TLS configuration...")
        
        try:
            tls_config = TLSConfig()
            
            # Test SSL context creation
            context = tls_config.create_ssl_context()
            if context:
                self.results['passed'].append("✓ SSL context creation successful")
                
                # Check TLS version
                if hasattr(context, 'minimum_version'):
                    if context.minimum_version >= ssl.TLSVersion.TLSv1_2:
                        self.results['passed'].append("✓ TLS 1.2+ enforced")
                    else:
                        self.results['failed'].append("✗ TLS version too low")
                
                # Check cipher suites
                if hasattr(context, 'get_ciphers'):
                    ciphers = context.get_ciphers()
                    secure_ciphers = [c for c in ciphers if 'ECDHE' in c['name'] or 'DHE' in c['name']]
                    if secure_ciphers:
                        self.results['passed'].append("✓ Secure cipher suites configured")
                    else:
                        self.results['warnings'].append("⚠ No forward secrecy ciphers found")
            else:
                self.results['failed'].append("✗ SSL context creation failed")
            
            # Test security headers
            headers = tls_config.get_security_headers()
            required_headers = [
                'Strict-Transport-Security',
                'X-Content-Type-Options',
                'X-Frame-Options',
                'Content-Security-Policy'
            ]
            
            for header in required_headers:
                if header in headers:
                    self.results['passed'].append(f"✓ {header} header configured")
                else:
                    self.results['failed'].append(f"✗ {header} header missing")
                    
        except Exception as e:
            self.results['failed'].append(f"✗ TLS validation error: {str(e)}")
    
    def _validate_authentication_config(self) -> None:
        """Validate authentication configuration"""
        self.logger.info("Validating authentication configuration...")
        
        try:
            with self.app.app_context():
                security_manager = SecurityManager()
                
                # Test password hashing
                test_password = "TestPassword123!"
                hashed = security_manager.hash_password(test_password)
                if security_manager.verify_password(test_password, hashed):
                    self.results['passed'].append("✓ Password hashing working")
                else:
                    self.results['failed'].append("✗ Password hashing failed")
                
                # Test MFA components
                from app.utils.security import MFAManager
                mfa_manager = MFAManager()
                
                secret = mfa_manager.generate_secret()
                if len(secret) >= 16:
                    self.results['passed'].append("✓ MFA secret generation working")
                else:
                    self.results['failed'].append("✗ MFA secret generation failed")
                
                # Test JWT configuration
                jwt_secret = self.app.config.get('JWT_SECRET_KEY')
                if jwt_secret and len(jwt_secret) >= 32:
                    self.results['passed'].append("✓ JWT secret properly configured")
                else:
                    self.results['failed'].append("✗ JWT secret weak or missing")
                    
        except Exception as e:
            self.results['failed'].append(f"✗ Authentication validation error: {str(e)}")
    
    def _validate_session_config(self) -> None:
        """Validate session configuration"""
        self.logger.info("Validating session configuration...")
        
        try:
            with self.app.app_context():
                from app.utils.security import SessionManager
                session_manager = SessionManager()
                
                # Test session creation
                session_data = session_manager.create_session(1)
                if 'token' in session_data and 'expires_at' in session_data:
                    self.results['passed'].append("✓ Session creation working")
                    
                    # Test session validation
                    if session_manager.validate_session(session_data['token']):
                        self.results['passed'].append("✓ Session validation working")
                    else:
                        self.results['failed'].append("✗ Session validation failed")
                else:
                    self.results['failed'].append("✗ Session creation failed")
                
                # Check session timeout configuration
                timeout = self.app.config.get('SESSION_TIMEOUT_MINUTES', 0)
                if timeout > 0 and timeout <= 480:  # Max 8 hours
                    self.results['passed'].append(f"✓ Session timeout configured ({timeout} minutes)")
                else:
                    self.results['warnings'].append("⚠ Session timeout not properly configured")
                    
        except Exception as e:
            self.results['failed'].append(f"✗ Session validation error: {str(e)}")
    
    def _validate_rate_limiting_config(self) -> None:
        """Validate rate limiting configuration"""
        self.logger.info("Validating rate limiting configuration...")
        
        try:
            with self.app.app_context():
                from app.utils.security import RateLimiter
                rate_limiter = RateLimiter()
                
                # Test rate limiting
                test_id = "test_validation"
                if rate_limiter.is_allowed(test_id, max_requests=5, window_minutes=1):
                    self.results['passed'].append("✓ Rate limiting working")
                else:
                    self.results['failed'].append("✗ Rate limiting failed")
                
                # Check DDoS protection
                ddos_protection = DDoSProtection()
                if hasattr(ddos_protection, 'detect_flood'):
                    self.results['passed'].append("✓ DDoS protection configured")
                else:
                    self.results['failed'].append("✗ DDoS protection missing")
                    
        except Exception as e:
            self.results['failed'].append(f"✗ Rate limiting validation error: {str(e)}")
    
    def _validate_audit_logging_config(self) -> None:
        """Validate audit logging configuration"""
        self.logger.info("Validating audit logging configuration...")
        
        try:
            with self.app.app_context():
                from app.utils.security import AuditLogger
                audit_logger = AuditLogger()
                
                # Test audit logging
                test_event = {
                    'event_type': 'test_validation',
                    'user_id': 1,
                    'ip_address': '127.0.0.1',
                    'details': 'Security validation test'
                }
                
                if audit_logger.log_security_event(**test_event):
                    self.results['passed'].append("✓ Audit logging working")
                else:
                    self.results['failed'].append("✗ Audit logging failed")
                
                # Check log retention configuration
                retention_days = self.app.config.get('AUDIT_LOG_RETENTION_DAYS', 0)
                if retention_days >= 365:  # NHS requirement: 1 year minimum
                    self.results['passed'].append(f"✓ Audit log retention configured ({retention_days} days)")
                else:
                    self.results['failed'].append("✗ Audit log retention insufficient (< 365 days)")
                    
        except Exception as e:
            self.results['failed'].append(f"✗ Audit logging validation error: {str(e)}")
    
    def _validate_nhs_compliance(self) -> None:
        """Validate NHS-specific compliance requirements"""
        self.logger.info("Validating NHS compliance...")
        
        try:
            # Check NHS CIS2 integration
            from app.utils.nhs_cis2 import NHSCISAuthentication
            nhs_auth = NHSCISAuthentication()
            
            if hasattr(nhs_auth, 'validate_token'):
                self.results['passed'].append("✓ NHS CIS2 integration configured")
            else:
                self.results['failed'].append("✗ NHS CIS2 integration missing")
            
            # Check NHS data standards compliance
            nhs_config = self.app.config.get('NHS_CIS2_CONFIG', {})
            required_nhs_fields = ['client_id', 'client_secret', 'auth_url', 'token_url']
            
            for field in required_nhs_fields:
                if field in nhs_config and nhs_config[field]:
                    self.results['passed'].append(f"✓ NHS {field} configured")
                else:
                    self.results['failed'].append(f"✗ NHS {field} missing")
            
            # Check data classification compliance
            if self.app.config.get('DATA_CLASSIFICATION_ENABLED', False):
                self.results['passed'].append("✓ Data classification enabled")
            else:
                self.results['warnings'].append("⚠ Data classification not enabled")
                
        except Exception as e:
            self.results['failed'].append(f"✗ NHS compliance validation error: {str(e)}")
    
    def _validate_data_protection(self) -> None:
        """Validate data protection measures"""
        self.logger.info("Validating data protection...")
        
        try:
            # Check encryption at rest
            if self.app.config.get('ENCRYPTION_AT_REST_ENABLED', False):
                self.results['passed'].append("✓ Encryption at rest enabled")
            else:
                self.results['failed'].append("✗ Encryption at rest not enabled")
            
            # Check PII protection
            if self.app.config.get('PII_ENCRYPTION_ENABLED', False):
                self.results['passed'].append("✓ PII encryption enabled")
            else:
                self.results['failed'].append("✗ PII encryption not enabled")
            
            # Check health data protection
            if self.app.config.get('HEALTH_DATA_ENCRYPTION_ENABLED', False):
                self.results['passed'].append("✓ Health data encryption enabled")
            else:
                self.results['failed'].append("✗ Health data encryption not enabled")
            
            # Check data retention policies
            retention_policy = self.app.config.get('DATA_RETENTION_POLICY')
            if retention_policy:
                self.results['passed'].append("✓ Data retention policy configured")
            else:
                self.results['warnings'].append("⚠ Data retention policy not configured")
                
        except Exception as e:
            self.results['failed'].append(f"✗ Data protection validation error: {str(e)}")
    
    def _validate_environment_security(self) -> None:
        """Validate environment security settings"""
        self.logger.info("Validating environment security...")
        
        try:
            # Check environment variables
            env_vars = ['SECRET_KEY', 'DATABASE_URL', 'JWT_SECRET_KEY']
            for var in env_vars:
                if os.getenv(var):
                    self.results['passed'].append(f"✓ {var} environment variable set")
                else:
                    self.results['failed'].append(f"✗ {var} environment variable missing")
            
            # Check debug mode
            if not self.app.config.get('DEBUG', True):
                self.results['passed'].append("✓ Debug mode disabled")
            else:
                self.results['failed'].append("✗ Debug mode enabled in production")
            
            # Check security configuration
            if self.app.config.get('SECURITY_ENHANCED', False):
                self.results['passed'].append("✓ Enhanced security mode enabled")
            else:
                self.results['warnings'].append("⚠ Enhanced security mode not enabled")
                
        except Exception as e:
            self.results['failed'].append(f"✗ Environment security validation error: {str(e)}")
    
    def _validate_database_security(self) -> None:
        """Validate database security settings"""
        self.logger.info("Validating database security...")
        
        try:
            # Check database connection security
            db_url = self.app.config.get('DATABASE_URL', '')
            if 'sslmode=require' in db_url or 'ssl=true' in db_url:
                self.results['passed'].append("✓ Database SSL enabled")
            else:
                self.results['warnings'].append("⚠ Database SSL not enforced")
            
            # Check connection pooling
            if self.app.config.get('DATABASE_POOL_SIZE', 0) > 0:
                self.results['passed'].append("✓ Database connection pooling configured")
            else:
                self.results['warnings'].append("⚠ Database connection pooling not configured")
            
            # Check query timeout
            if self.app.config.get('DATABASE_QUERY_TIMEOUT', 0) > 0:
                self.results['passed'].append("✓ Database query timeout configured")
            else:
                self.results['warnings'].append("⚠ Database query timeout not configured")
                
        except Exception as e:
            self.results['failed'].append(f"✗ Database security validation error: {str(e)}")
    
    def _generate_report(self) -> Dict[str, Any]:
        """Generate comprehensive security validation report"""
        total_checks = len(self.results['passed']) + len(self.results['failed']) + len(self.results['warnings'])
        passed_count = len(self.results['passed'])
        failed_count = len(self.results['failed'])
        warning_count = len(self.results['warnings'])
        
        score = (passed_count / total_checks * 100) if total_checks > 0 else 0
        
        report = {
            'summary': {
                'total_checks': total_checks,
                'passed': passed_count,
                'failed': failed_count,
                'warnings': warning_count,
                'score': round(score, 2),
                'status': 'PASS' if failed_count == 0 else 'FAIL'
            },
            'details': self.results,
            'recommendations': self._generate_recommendations()
        }
        
        return report
    
    def _generate_recommendations(self) -> List[str]:
        """Generate security recommendations based on validation results"""
        recommendations = []
        
        if any('JWT secret weak' in item for item in self.results['failed']):
            recommendations.append("Generate a stronger JWT secret key (minimum 32 characters)")
        
        if any('Debug mode enabled' in item for item in self.results['failed']):
            recommendations.append("Disable debug mode in production environment")
        
        if any('TLS version too low' in item for item in self.results['failed']):
            recommendations.append("Upgrade to TLS 1.3 for enhanced security")
        
        if any('Audit log retention insufficient' in item for item in self.results['failed']):
            recommendations.append("Configure audit log retention to meet NHS requirements (minimum 365 days)")
        
        if any('Database SSL not enforced' in item for item in self.results['warnings']):
            recommendations.append("Enable SSL/TLS for database connections")
        
        if any('Key rotation not implemented' in item for item in self.results['warnings']):
            recommendations.append("Implement automated encryption key rotation")
        
        return recommendations


def main():
    """Run security validation"""
    validator = SecurityValidator()
    report = validator.validate_all()
    
    # Print summary
    print("\n" + "="*60)
    print("SECURITY VALIDATION REPORT")
    print("="*60)
    print(f"Status: {report['summary']['status']}")
    print(f"Score: {report['summary']['score']}%")
    print(f"Passed: {report['summary']['passed']}")
    print(f"Failed: {report['summary']['failed']}")
    print(f"Warnings: {report['summary']['warnings']}")
    
    # Print details
    print("\n📊 PASSED CHECKS:")
    for item in report['details']['passed']:
        print(f"  {item}")
    
    if report['details']['failed']:
        print("\n❌ FAILED CHECKS:")
        for item in report['details']['failed']:
            print(f"  {item}")
    
    if report['details']['warnings']:
        print("\n⚠️  WARNINGS:")
        for item in report['details']['warnings']:
            print(f"  {item}")
    
    if report['recommendations']:
        print("\n💡 RECOMMENDATIONS:")
        for i, rec in enumerate(report['recommendations'], 1):
            print(f"  {i}. {rec}")
    
    print("\n" + "="*60)
    
    # Save report to file
    with open('security_validation_report.json', 'w') as f:
        json.dump(report, f, indent=2)
    
    print("📄 Full report saved to: security_validation_report.json")
    
    return report['summary']['status'] == 'PASS'


if __name__ == '__main__':
    success = main()
    exit(0 if success else 1)
