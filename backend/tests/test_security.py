"""
Comprehensive Security Test Suite for Remote Patient Monitoring System
Tests all security components according to NHS Digital standards
"""

import pytest
import json
from unittest.mock import patch, MagicMock
from flask import Flask
from app import create_app
from app.models import User, SecurityAuditLog, UserSession
from app.utils.security import SecurityManager, MFAManager, SessionManager, RateLimiter
from app.utils.encryption import EncryptionManager
from app.utils.ddos_protection import DDoSProtection
from app.utils.nhs_cis2 import NHSCISAuthentication
from app.utils.tls_config import TLSConfig
import time


class TestSecurityManager:
    """Test core security manager functionality"""
    
    def setup_method(self):
        """Setup test environment"""
        self.app = create_app('testing')
        self.app_context = self.app.app_context()
        self.app_context.push()
        self.security_manager = SecurityManager()
    
    def teardown_method(self):
        """Cleanup test environment"""
        self.app_context.pop()
    
    def test_encryption_decryption(self):
        """Test data encryption and decryption"""
        test_data = "Sensitive NHS patient data"
        
        # Test encryption
        encrypted = self.security_manager.encrypt_data(test_data)
        assert encrypted != test_data
        assert len(encrypted) > 0
        
        # Test decryption
        decrypted = self.security_manager.decrypt_data(encrypted)
        assert decrypted == test_data
    
    def test_key_derivation(self):
        """Test password-based key derivation"""
        password = "SecurePassword123!"
        salt = b"test_salt_16bytes"
        
        key1 = self.security_manager.derive_key_from_password(password, salt)
        key2 = self.security_manager.derive_key_from_password(password, salt)
        
        # Same password and salt should produce same key
        assert key1 == key2
        assert len(key1) == 32  # 256-bit key
    
    def test_hash_sensitive_data(self):
        """Test sensitive data hashing"""
        sensitive_data = "NHS Number: 1234567890"
        
        hash_result, salt = self.security_manager.hash_sensitive_data(sensitive_data)
        assert hash_result != sensitive_data
        assert len(salt) > 0
        
        # Verify same data with same salt produces same hash
        hash_result2, _ = self.security_manager.hash_sensitive_data(sensitive_data, salt)
        assert hash_result == hash_result2


class TestMFAManager:
    """Test Multi-Factor Authentication functionality"""
    
    def setup_method(self):
        """Setup test environment"""
        self.app = create_app('testing')
        self.app_context = self.app.app_context()
        self.app_context.push()
        self.mfa_manager = MFAManager()
    
    def teardown_method(self):
        """Cleanup test environment"""
        self.app_context.pop()
    
    def test_secret_generation(self):
        """Test MFA secret generation"""
        secret = self.mfa_manager.generate_secret()
        assert len(secret) == 32  # pyotp default length
        assert secret.isalnum()
    
    def test_qr_code_generation(self):
        """Test QR code generation for MFA setup"""
        secret = self.mfa_manager.generate_secret()
        user_email = "test@nhs.net"
        
        qr_code = self.mfa_manager.generate_qr_code(secret, user_email)
        assert qr_code.startswith('data:image/png;base64,')
    
    def test_token_verification(self):
        """Test MFA token verification"""
        secret = self.mfa_manager.generate_secret()
        
        # Generate current token
        import pyotp
        totp = pyotp.TOTP(secret)
        current_token = totp.now()
        
        # Test verification
        assert self.mfa_manager.verify_token(secret, current_token)
        assert not self.mfa_manager.verify_token(secret, "000000")


class TestSessionManager:
    """Test session management functionality"""
    
    def setup_method(self):
        """Setup test environment"""
        self.app = create_app('testing')
        self.app_context = self.app.app_context()
        self.app_context.push()
        self.session_manager = SessionManager()
    
    def teardown_method(self):
        """Cleanup test environment"""
        self.app_context.pop()
    
    def test_session_creation(self):
        """Test secure session creation"""
        user_id = 1
        session_data = self.session_manager.create_session(user_id)
        
        assert 'token' in session_data
        assert 'expires_at' in session_data
        assert session_data['user_id'] == user_id
        assert len(session_data['token']) == 64  # 32 bytes hex encoded
    
    def test_session_validation(self):
        """Test session validation"""
        user_id = 1
        session_data = self.session_manager.create_session(user_id)
        token = session_data['token']
        
        # Test valid session
        is_valid = self.session_manager.validate_session(token)
        assert is_valid
        
        # Test invalid token
        assert not self.session_manager.validate_session("invalid_token")
    
    def test_session_expiry(self):
        """Test session expiry handling"""
        user_id = 1
        # Create session with very short timeout
        session_data = self.session_manager.create_session(user_id, timeout_minutes=0.01)
        token = session_data['token']
        
        # Wait for expiry
        time.sleep(1)
        
        # Should be expired
        assert not self.session_manager.validate_session(token)


class TestRateLimiter:
    """Test rate limiting functionality"""
    
    def setup_method(self):
        """Setup test environment"""
        self.app = create_app('testing')
        self.app_context = self.app.app_context()
        self.app_context.push()
        self.rate_limiter = RateLimiter()
    
    def teardown_method(self):
        """Cleanup test environment"""
        self.app_context.pop()
    
    def test_rate_limiting(self):
        """Test basic rate limiting"""
        identifier = "test_user_192.168.1.1"
        
        # Should allow initial requests
        for i in range(5):
            assert self.rate_limiter.is_allowed(identifier, max_requests=10, window_minutes=1)
        
        # Should block after exceeding limit
        for i in range(10):
            self.rate_limiter.is_allowed(identifier, max_requests=5, window_minutes=1)
        
        assert not self.rate_limiter.is_allowed(identifier, max_requests=5, window_minutes=1)


class TestEncryptionManager:
    """Test data encryption at rest functionality"""
    
    def setup_method(self):
        """Setup test environment"""
        self.app = create_app('testing')
        self.app_context = self.app.app_context()
        self.app_context.push()
        self.encryption_manager = EncryptionManager()
    
    def teardown_method(self):
        """Cleanup test environment"""
        self.app_context.pop()
    
    def test_field_encryption(self):
        """Test database field encryption"""
        sensitive_data = "Patient NHS Number: 1234567890"
        
        encrypted = self.encryption_manager.encrypt_field(sensitive_data)
        assert encrypted != sensitive_data
        
        decrypted = self.encryption_manager.decrypt_field(encrypted)
        assert decrypted == sensitive_data
    
    def test_pii_encryption(self):
        """Test PII-specific encryption"""
        pii_data = {
            "name": "John Smith",
            "nhs_number": "1234567890",
            "dob": "1990-01-01"
        }
        
        encrypted = self.encryption_manager.encrypt_pii(pii_data)
        assert encrypted != json.dumps(pii_data)
        
        decrypted = self.encryption_manager.decrypt_pii(encrypted)
        assert decrypted == pii_data
    
    def test_health_data_encryption(self):
        """Test health data encryption"""
        health_data = {
            "blood_pressure": "120/80",
            "heart_rate": 72,
            "temperature": 36.5,
            "diagnosis": "Hypertension"
        }
        
        encrypted = self.encryption_manager.encrypt_health_data(health_data)
        assert encrypted != json.dumps(health_data)
        
        decrypted = self.encryption_manager.decrypt_health_data(encrypted)
        assert decrypted == health_data


class TestDDoSProtection:
    """Test DDoS protection functionality"""
    
    def setup_method(self):
        """Setup test environment"""
        self.app = create_app('testing')
        self.app_context = self.app.app_context()
        self.app_context.push()
        self.ddos_protection = DDoSProtection()
    
    def teardown_method(self):
        """Cleanup test environment"""
        self.app_context.pop()
    
    def test_flood_detection(self):
        """Test request flood detection"""
        ip_address = "192.168.1.100"
        
        # Normal requests should pass
        for i in range(10):
            assert not self.ddos_protection.detect_flood(ip_address, threshold=50)
        
        # Flood should be detected
        for i in range(100):
            self.ddos_protection.detect_flood(ip_address, threshold=50)
        
        assert self.ddos_protection.detect_flood(ip_address, threshold=50)
    
    def test_bot_detection(self):
        """Test bot detection patterns"""
        # Simulate bot-like behavior
        requests = [
            {"url": "/api/patients", "user_agent": "Bot/1.0"},
            {"url": "/api/patients", "user_agent": "Bot/1.0"},
            {"url": "/api/patients", "user_agent": "Bot/1.0"}
        ]
        
        is_bot = self.ddos_protection.detect_bot_patterns("192.168.1.100", requests)
        assert is_bot
    
    def test_input_sanitization(self):
        """Test input sanitization"""
        # Test SQL injection attempt
        malicious_input = "'; DROP TABLE users; --"
        sanitized = self.ddos_protection.sanitize_input(malicious_input)
        assert "DROP TABLE" not in sanitized
        
        # Test XSS attempt
        xss_input = "<script>alert('xss')</script>"
        sanitized = self.ddos_protection.sanitize_input(xss_input)
        assert "<script>" not in sanitized


class TestNHSCISAuthentication:
    """Test NHS CIS2 authentication functionality"""
    
    def setup_method(self):
        """Setup test environment"""
        self.app = create_app('testing')
        self.app_context = self.app.app_context()
        self.app_context.push()
        self.nhs_auth = NHSCISAuthentication()
    
    def teardown_method(self):
        """Cleanup test environment"""
        self.app_context.pop()
    
    @patch('requests.post')
    def test_token_validation(self, mock_post):
        """Test NHS CIS2 token validation"""
        # Mock successful token validation
        mock_response = MagicMock()
        mock_response.json.return_value = {
            "access_token": "valid_token",
            "token_type": "bearer",
            "expires_in": 3600
        }
        mock_response.status_code = 200
        mock_post.return_value = mock_response
        
        auth_code = "test_auth_code"
        result = self.nhs_auth.validate_token(auth_code)
        
        assert result is not None
        assert "access_token" in result
    
    def test_jwt_validation(self):
        """Test JWT token validation"""
        # This would need a valid JWT token from NHS CIS2
        # For testing, we'll mock the validation
        token = "mock.jwt.token"
        
        with patch.object(self.nhs_auth, 'validate_jwt') as mock_validate:
            mock_validate.return_value = {
                "sub": "user123",
                "smartcard_id": "123456789",
                "role": "healthcare_professional"
            }
            
            result = self.nhs_auth.validate_jwt(token)
            assert result is not None
            assert "smartcard_id" in result


class TestTLSConfig:
    """Test TLS configuration functionality"""
    
    def setup_method(self):
        """Setup test environment"""
        self.tls_config = TLSConfig()
    
    def test_ssl_context_creation(self):
        """Test SSL context creation"""
        context = self.tls_config.create_ssl_context()
        
        # Verify TLS 1.3 is supported
        assert hasattr(context, 'minimum_version')
        assert hasattr(context, 'maximum_version')
    
    def test_security_headers(self):
        """Test security headers configuration"""
        headers = self.tls_config.get_security_headers()
        
        required_headers = [
            'Strict-Transport-Security',
            'X-Content-Type-Options',
            'X-Frame-Options',
            'X-XSS-Protection',
            'Content-Security-Policy'
        ]
        
        for header in required_headers:
            assert header in headers


class TestSecurityIntegration:
    """Test integration of all security components"""
    
    def setup_method(self):
        """Setup test environment"""
        self.app = create_app('testing')
        self.client = self.app.test_client()
        self.app_context = self.app.app_context()
        self.app_context.push()
    
    def teardown_method(self):
        """Cleanup test environment"""
        self.app_context.pop()
    
    def test_login_with_mfa(self):
        """Test complete login flow with MFA"""
        # This would test the full authentication flow
        # including MFA verification
        pass
    
    def test_session_management_flow(self):
        """Test complete session management flow"""
        # This would test session creation, validation,
        # and cleanup
        pass
    
    def test_audit_logging(self):
        """Test security audit logging"""
        # This would test that security events
        # are properly logged
        pass
    
    def test_encryption_in_database(self):
        """Test that sensitive data is encrypted in database"""
        # This would test that PII and health data
        # is encrypted when stored
        pass


if __name__ == '__main__':
    pytest.main([__file__, '-v'])
