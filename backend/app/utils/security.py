"""
Security utilities for the Remote Patient Monitoring application
Implements comprehensive security measures according to NHS Digital standards
"""

import os
import secrets
import hashlib
import base64
import time
from datetime import datetime, timedelta
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from flask import current_app, request
from werkzeug.security import generate_password_hash, check_password_hash
import jwt
import pyotp
import qrcode
from io import BytesIO
import logging
from typing import Optional, Dict, Any, Union, Tuple
from .security_errors import (
    SecurityError, EncryptionError, AuthenticationError, 
    SessionError, MFAError, handle_encryption_errors,
    handle_authentication_errors, handle_session_errors,
    handle_mfa_errors
)

logger = logging.getLogger(__name__)

class SecurityManager:
    """Comprehensive security management class"""
    
    def __init__(self):
        self.failed_attempts = {}
        self.lockout_duration = 30  # 30 minutes
        self.max_attempts = 5
        
    def generate_encryption_key(self):
        """Generate a new encryption key"""
        return Fernet.generate_key()
    
    @handle_encryption_errors
    def derive_key_from_password(self, password: str, salt: Optional[bytes] = None) -> bytes:
        """Derive encryption key from password using PBKDF2"""
        try:
            if salt is None:
                salt = os.urandom(16)
            
            kdf = PBKDF2HMAC(
                algorithm=hashes.SHA256(),
                length=32,
                salt=salt,
                iterations=100000,
            )
            return base64.urlsafe_b64encode(kdf.derive(password.encode()))
        except Exception as e:
            logger.error(f"Key derivation failed: {str(e)}")
            raise EncryptionError(f"Failed to derive key from password: {str(e)}")
    
    @handle_encryption_errors
    def encrypt_data(self, data: str, key: Optional[bytes] = None) -> str:
        """Encrypt sensitive data using Fernet encryption"""
        try:
            if key is None:
                key = current_app.config.get('ENCRYPTION_KEY')
                if not key:
                    raise EncryptionError("No encryption key configured")
            
            f = Fernet(key)
            encrypted_data = f.encrypt(data.encode())
            return base64.urlsafe_b64encode(encrypted_data).decode()
        except Exception as e:
            logger.error(f"Encryption failed: {str(e)}")
            raise EncryptionError(f"Failed to encrypt data: {str(e)}")
    
    @handle_encryption_errors
    def decrypt_data(self, encrypted_data: str, key: Optional[bytes] = None) -> str:
        """Decrypt data using Fernet encryption"""
        try:
            if key is None:
                key = current_app.config.get('ENCRYPTION_KEY')
                if not key:
                    raise EncryptionError("No encryption key configured")
            
            f = Fernet(key)
            decoded_data = base64.urlsafe_b64decode(encrypted_data.encode())
            decrypted_data = f.decrypt(decoded_data)
            return decrypted_data.decode()
        except Exception as e:
            logger.error(f"Decryption failed: {str(e)}")
            raise EncryptionError(f"Failed to decrypt data: {str(e)}")
    
    @handle_encryption_errors
    def hash_sensitive_data(self, data: str, salt: Optional[str] = None) -> Tuple[str, str]:
        """Hash sensitive data with salt"""
        if salt is None:
            salt = secrets.token_hex(32)
        
        hash_obj = hashlib.sha256()
        hash_obj.update((data + salt).encode())
        return hash_obj.hexdigest(), salt
    
    def verify_hash(self, data: str, hashed_data: str, salt: str) -> bool:
        """Verify hashed data"""
        hash_obj = hashlib.sha256()
        hash_obj.update((data + salt).encode())
        return hash_obj.hexdigest() == hashed_data
    
    def hash_password(self, password: str) -> str:
        """Hash password using Werkzeug security"""
        return generate_password_hash(password)
    
    def check_password(self, password: str, password_hash: str) -> bool:
        """Verify password against hash"""
        return check_password_hash(password_hash, password)
    
    def generate_random_password(self, length: int = 16) -> str:
        """Generate secure random password"""
        import string
        alphabet = string.ascii_letters + string.digits + "!@#$%^&*"
        return ''.join(secrets.choice(alphabet) for _ in range(length))

class MFAManager:
    """Multi-Factor Authentication management"""
    
    def generate_secret(self) -> str:
        """Generate TOTP secret for MFA"""
        return pyotp.random_base32()
    
    def generate_qr_code(self, user_email: str, secret: str) -> BytesIO:
        """Generate QR code for MFA setup"""
        totp_uri = pyotp.totp.TOTP(secret).provisioning_uri(
            name=user_email,
            issuer_name="NHS Remote Patient Monitoring"
        )
        
        qr = qrcode.QRCode(version=1, box_size=10, border=5)
        qr.add_data(totp_uri)
        qr.make(fit=True)
        
        img = qr.make_image(fill_color="black", back_color="white")
        
        # Save to BytesIO
        img_buffer = BytesIO()
        img.save(img_buffer, format='PNG')
        img_buffer.seek(0)
        
        return img_buffer
    
    def verify_totp(self, secret: str, token: str) -> bool:
        """Verify TOTP token"""
        totp = pyotp.TOTP(secret)
        return totp.verify(token, valid_window=1)  # Allow 30-second window
    
    def generate_backup_codes(self, count: int = 10) -> list:
        """Generate backup codes for MFA"""
        return [secrets.token_hex(6).upper() for _ in range(count)]

class SessionManager:
    """Session management with timeout and security"""
    
    def __init__(self):
        self.active_sessions = {}
        self.session_timeout = timedelta(minutes=120)  # 2 hours default
    
    def create_session(self, user_id: int, ip_address: str, user_agent: str) -> str:
        """Create secure session"""
        session_id = secrets.token_urlsafe(32)
        
        session_data = {
            'user_id': user_id,
            'ip_address': ip_address,
            'user_agent': user_agent,
            'created_at': datetime.utcnow(),
            'last_activity': datetime.utcnow(),
            'expires_at': datetime.utcnow() + self.session_timeout
        }
        
        self.active_sessions[session_id] = session_data
        return session_id
    
    def validate_session(self, session_id: str, ip_address: str, user_agent: str) -> Optional[dict]:
        """Validate session and check for security issues"""
        if session_id not in self.active_sessions:
            return None
        
        session = self.active_sessions[session_id]
        
        # Check if session expired
        if datetime.utcnow() > session['expires_at']:
            self.destroy_session(session_id)
            return None
        
        # Check IP address (optional, based on configuration)
        if current_app.config.get('STRICT_IP_VALIDATION', False):
            if session['ip_address'] != ip_address:
                logger.warning(f"Session {session_id} IP mismatch: {session['ip_address']} vs {ip_address}")
                self.destroy_session(session_id)
                return None
        
        # Update last activity
        session['last_activity'] = datetime.utcnow()
        session['expires_at'] = datetime.utcnow() + self.session_timeout
        
        return session
    
    def destroy_session(self, session_id: str):
        """Destroy session"""
        if session_id in self.active_sessions:
            del self.active_sessions[session_id]
    
    def invalidate_session(self, user_id: int):
        """Invalidate all sessions for a user"""
        sessions_to_remove = []
        for session_id, session_data in self.active_sessions.items():
            if session_data['user_id'] == user_id:
                sessions_to_remove.append(session_id)
        
        for session_id in sessions_to_remove:
            self.destroy_session(session_id)
    
    def cleanup_expired_sessions(self):
        """Clean up expired sessions"""
        expired_sessions = []
        current_time = datetime.utcnow()
        
        for session_id, session_data in self.active_sessions.items():
            if current_time > session_data['expires_at']:
                expired_sessions.append(session_id)
        
        for session_id in expired_sessions:
            self.destroy_session(session_id)

class RateLimiter:
    """Rate limiting for API endpoints"""
    
    def __init__(self):
        self.requests = {}
        self.cleanup_interval = 3600  # 1 hour
        self.last_cleanup = time.time()
    
    def is_allowed(self, identifier: str, limit: int, window: int) -> tuple:
        """
        Check if request is allowed under rate limit
        Returns (is_allowed, requests_made, time_until_reset)
        """
        current_time = time.time()
        
        # Clean up old entries periodically
        if current_time - self.last_cleanup > self.cleanup_interval:
            self._cleanup_old_entries()
            self.last_cleanup = current_time
        
        if identifier not in self.requests:
            self.requests[identifier] = []
        
        # Remove requests outside the window
        self.requests[identifier] = [
            req_time for req_time in self.requests[identifier]
            if current_time - req_time < window
        ]
        
        requests_count = len(self.requests[identifier])
        
        if requests_count >= limit:
            # Calculate time until oldest request expires
            oldest_request = min(self.requests[identifier])
            time_until_reset = window - (current_time - oldest_request)
            return False, requests_count, time_until_reset
        
        # Add current request
        self.requests[identifier].append(current_time)
        return True, requests_count + 1, 0
    
    def _cleanup_old_entries(self):
        """Clean up old rate limit entries"""
        current_time = time.time()
        cleanup_threshold = 3600  # 1 hour
        
        identifiers_to_remove = []
        
        for identifier, request_times in self.requests.items():
            # Remove old requests
            recent_requests = [
                req_time for req_time in request_times
                if current_time - req_time < cleanup_threshold
            ]
            
            if recent_requests:
                self.requests[identifier] = recent_requests
            else:
                identifiers_to_remove.append(identifier)
        
        # Remove empty entries
        for identifier in identifiers_to_remove:
            del self.requests[identifier]

class IPWhitelistManager:
    """IP whitelist management for enhanced security"""
    
    def __init__(self):
        self.whitelist = set()
        self.load_whitelist()
    
    def load_whitelist(self):
        """Load IP whitelist from configuration"""
        whitelist_config = current_app.config.get('IP_WHITELIST', [])
        for ip_range in whitelist_config:
            self.whitelist.add(ip_range)
    
    def is_ip_allowed(self, ip_address: str) -> bool:
        """Check if IP address is in whitelist"""
        if not self.whitelist:
            return True  # No whitelist configured, allow all
        
        # Simple IP checking (can be enhanced with CIDR support)
        return ip_address in self.whitelist or self._check_ip_range(ip_address)
    
    def _check_ip_range(self, ip_address: str) -> bool:
        """Check if IP is in any configured range (basic implementation)"""
        # This is a simplified version - in production, use ipaddress module
        for ip_range in self.whitelist:
            if '*' in ip_range:
                pattern = ip_range.replace('*', '.*')
                import re
                if re.match(pattern, ip_address):
                    return True
        return False

class AuditLogger:
    """Security audit logging"""
    
    def __init__(self):
        self.logger = logging.getLogger('security_audit')
    
    def log_authentication_attempt(self, email: str, ip_address: str, success: bool, reason: str = ""):
        """Log authentication attempts"""
        event = {
            'event_type': 'authentication',
            'email': email,
            'ip_address': ip_address,
            'success': success,
            'reason': reason,
            'timestamp': datetime.utcnow().isoformat(),
            'user_agent': request.headers.get('User-Agent') if request else None
        }
        
        if success:
            self.logger.info(f"Authentication success: {email} from {ip_address}")
        else:
            self.logger.warning(f"Authentication failed: {email} from {ip_address} - {reason}")
    
    def log_security_event(self, event_type: str, user_id: int, description: str, severity: str = 'info'):
        """Log security events"""
        event = {
            'event_type': event_type,
            'user_id': user_id,
            'description': description,
            'severity': severity,
            'timestamp': datetime.utcnow().isoformat(),
            'ip_address': request.remote_addr if request else None
        }
        
        log_method = getattr(self.logger, severity, self.logger.info)
        log_method(f"Security event: {event_type} - {description}")
    
    def log_data_access(self, user_id: int, resource_type: str, resource_id: str, action: str):
        """Log data access events"""
        event = {
            'event_type': 'data_access',
            'user_id': user_id,
            'resource_type': resource_type,
            'resource_id': resource_id,
            'action': action,
            'timestamp': datetime.utcnow().isoformat(),
            'ip_address': request.remote_addr if request else None
        }
        
        self.logger.info(f"Data access: User {user_id} {action} {resource_type} {resource_id}")

# Initialize security components
security_manager = SecurityManager()
mfa_manager = MFAManager()
session_manager = SessionManager()
rate_limiter = RateLimiter()
ip_whitelist_manager = IPWhitelistManager()
audit_logger = AuditLogger()
