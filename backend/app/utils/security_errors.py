"""
Enhanced Error Handling for Security Components
Comprehensive error handling with NHS Digital compliance logging
"""

import logging
import traceback
import json
from datetime import datetime
from typing import Any, Dict, Optional, Callable
from functools import wraps
from flask import current_app, request, jsonify
from app.utils.security import AuditLogger


class SecurityError(Exception):
    """Base class for security-related errors"""
    
    def __init__(self, message: str, error_code: Optional[str] = None, details: Optional[Dict[str, Any]] = None):
        self.message = message
        self.error_code = error_code or 'SEC_ERR_UNKNOWN'
        self.details = details or {}
        self.timestamp = datetime.utcnow()
        super().__init__(self.message)


class AuthenticationError(SecurityError):
    """Authentication-related errors"""
    
    def __init__(self, message: str, details: Optional[Dict[str, Any]] = None):
        super().__init__(message, 'SEC_ERR_AUTH', details)


class AuthorizationError(SecurityError):
    """Authorization-related errors"""
    
    def __init__(self, message: str, details: Optional[Dict[str, Any]] = None):
        super().__init__(message, 'SEC_ERR_AUTHZ', details)


class EncryptionError(SecurityError):
    """Encryption/decryption errors"""
    
    def __init__(self, message: str, details: Optional[Dict[str, Any]] = None):
        super().__init__(message, 'SEC_ERR_ENCRYPT', details)


class SessionError(SecurityError):
    """Session management errors"""
    
    def __init__(self, message: str, details: Optional[Dict[str, Any]] = None):
        super().__init__(message, 'SEC_ERR_SESSION', details)


class MFAError(SecurityError):
    """Multi-factor authentication errors"""
    
    def __init__(self, message: str, details: Optional[Dict[str, Any]] = None):
        super().__init__(message, 'SEC_ERR_MFA', details)


class NHSComplianceError(SecurityError):
    """NHS compliance-related errors"""
    
    def __init__(self, message: str, details: Optional[Dict[str, Any]] = None):
        super().__init__(message, 'SEC_ERR_NHS', details)


class RateLimitError(SecurityError):
    """Rate limiting errors"""
    
    def __init__(self, message: str, details: Optional[Dict[str, Any]] = None):
        super().__init__(message, 'SEC_ERR_RATE_LIMIT', details)


class DDoSError(SecurityError):
    """DDoS protection errors"""
    
    def __init__(self, message: str, details: Optional[Dict[str, Any]] = None):
        super().__init__(message, 'SEC_ERR_DDOS', details)


class SecurityErrorHandler:
    """Centralized security error handling"""
    
    def __init__(self):
        self.audit_logger = AuditLogger()
        self.logger = logging.getLogger(__name__)
        
        # Error response templates
        self.error_responses = {
            'SEC_ERR_AUTH': {
                'status_code': 401,
                'message': 'Authentication failed',
                'user_message': 'Invalid credentials provided'
            },
            'SEC_ERR_AUTHZ': {
                'status_code': 403,
                'message': 'Authorization failed',
                'user_message': 'Insufficient permissions'
            },
            'SEC_ERR_ENCRYPT': {
                'status_code': 500,
                'message': 'Encryption operation failed',
                'user_message': 'Security operation failed'
            },
            'SEC_ERR_SESSION': {
                'status_code': 401,
                'message': 'Session validation failed',
                'user_message': 'Please log in again'
            },
            'SEC_ERR_MFA': {
                'status_code': 401,
                'message': 'Multi-factor authentication failed',
                'user_message': 'Invalid verification code'
            },
            'SEC_ERR_NHS': {
                'status_code': 403,
                'message': 'NHS compliance violation',
                'user_message': 'Access denied - compliance requirements not met'
            },
            'SEC_ERR_RATE_LIMIT': {
                'status_code': 429,
                'message': 'Rate limit exceeded',
                'user_message': 'Too many requests - please try again later'
            },
            'SEC_ERR_DDOS': {
                'status_code': 503,
                'message': 'DDoS protection activated',
                'user_message': 'Service temporarily unavailable'
            }
        }
    
    def handle_security_error(self, error: SecurityError, request_context: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """Handle security errors with logging and monitoring"""
        
        # Get request context if not provided
        if request_context is None:
            request_context = self._get_request_context()
        
        # Log security error
        self._log_security_error(error, request_context)
        
        # Get appropriate response
        response_template = self.error_responses.get(
            error.error_code, 
            self.error_responses['SEC_ERR_AUTH']
        )
        
        # Create error response
        error_response = {
            'error': True,
            'error_code': error.error_code,
            'message': response_template['user_message'],
            'timestamp': error.timestamp.isoformat(),
            'request_id': request_context.get('request_id')
        }
        
        # Add debug information in development
        if current_app.config.get('DEBUG', False):
            error_response['debug'] = {
                'internal_message': error.message,
                'details': error.details,
                'traceback': traceback.format_exc()
            }
        
        return {
            'response': error_response,
            'status_code': response_template['status_code']
        }
    
    def _get_request_context(self) -> Dict[str, Any]:
        """Extract request context information"""
        context = {}
        
        if request:
            context.update({
                'ip_address': request.remote_addr,
                'user_agent': request.headers.get('User-Agent'),
                'method': request.method,
                'url': request.url,
                'endpoint': request.endpoint,
                'request_id': getattr(request, 'id', None)
            })
        
        return context
    
    def _log_security_error(self, error: SecurityError, context: Dict[str, Any]) -> None:
        """Log security error with full context"""
        try:
            # Log to application logger
            self.logger.error(
                f"Security Error [{error.error_code}]: {error.message}",
                extra={
                    'error_code': error.error_code,
                    'error_details': error.details,
                    'request_context': context,
                    'timestamp': error.timestamp.isoformat()
                }
            )
            
            # Log to security audit
            self.audit_logger.log_security_event(
                event_type='security_error',
                user_id=context.get('user_id', 0),
                description=f"{error.error_code}: {error.message}",
                severity='error'
            )
            
        except Exception as log_error:
            # Fallback logging if main logging fails
            print(f"Logging error occurred: {str(log_error)}")
            print(f"Original security error: {error.message}")


def security_error_handler(func: Callable) -> Callable:
    """Decorator for handling security errors in functions"""
    
    @wraps(func)
    def wrapper(*args, **kwargs):
        error_handler = SecurityErrorHandler()
        
        try:
            return func(*args, **kwargs)
            
        except SecurityError as e:
            # Handle known security errors
            error_response = error_handler.handle_security_error(e)
            return jsonify(error_response['response']), error_response['status_code']
            
        except Exception as e:
            # Handle unexpected errors as security errors
            security_error = SecurityError(
                message=f"Unexpected security error: {str(e)}",
                error_code='SEC_ERR_UNKNOWN',
                details={'original_error': str(e), 'type': type(e).__name__}
            )
            
            error_response = error_handler.handle_security_error(security_error)
            return jsonify(error_response['response']), error_response['status_code']
    
    return wrapper


def handle_authentication_errors(func: Callable) -> Callable:
    """Decorator specifically for authentication error handling"""
    
    @wraps(func)
    def wrapper(*args, **kwargs):
        try:
            return func(*args, **kwargs)
        except Exception as e:
            raise AuthenticationError(
                message=f"Authentication failed: {str(e)}",
                details={'original_error': str(e)}
            )
    
    return wrapper


def handle_encryption_errors(func: Callable) -> Callable:
    """Decorator specifically for encryption error handling"""
    
    @wraps(func)
    def wrapper(*args, **kwargs):
        try:
            return func(*args, **kwargs)
        except Exception as e:
            raise EncryptionError(
                message=f"Encryption operation failed: {str(e)}",
                details={'original_error': str(e)}
            )
    
    return wrapper


def handle_session_errors(func: Callable) -> Callable:
    """Decorator specifically for session error handling"""
    
    @wraps(func)
    def wrapper(*args, **kwargs):
        try:
            return func(*args, **kwargs)
        except Exception as e:
            raise SessionError(
                message=f"Session operation failed: {str(e)}",
                details={'original_error': str(e)}
            )
    
    return wrapper


def handle_mfa_errors(func: Callable) -> Callable:
    """Decorator specifically for MFA error handling"""
    
    @wraps(func)
    def wrapper(*args, **kwargs):
        try:
            return func(*args, **kwargs)
        except Exception as e:
            raise MFAError(
                message=f"MFA operation failed: {str(e)}",
                details={'original_error': str(e)}
            )
    
    return wrapper


def handle_nhs_compliance_errors(func: Callable) -> Callable:
    """Decorator specifically for NHS compliance error handling"""
    
    @wraps(func)
    def wrapper(*args, **kwargs):
        try:
            return func(*args, **kwargs)
        except Exception as e:
            raise NHSComplianceError(
                message=f"NHS compliance check failed: {str(e)}",
                details={'original_error': str(e)}
            )
    
    return wrapper


class SecurityErrorLogger:
    """Enhanced logging for security errors"""
    
    def __init__(self):
        self.logger = logging.getLogger('security_errors')
        self.audit_logger = AuditLogger()
        
        # Configure security error logger
        if not self.logger.handlers:
            handler = logging.FileHandler('logs/security_errors.log')
            formatter = logging.Formatter(
                '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
            )
            handler.setFormatter(formatter)
            self.logger.addHandler(handler)
            self.logger.setLevel(logging.INFO)
    
    def log_error(self, error: SecurityError, context: Optional[Dict[str, Any]] = None) -> None:
        """Log security error with enhanced context"""
        
        error_data = {
            'error_code': error.error_code,
            'message': error.message,
            'details': error.details,
            'timestamp': error.timestamp.isoformat(),
            'context': context or {}
        }
        
        # Log to file
        self.logger.error(json.dumps(error_data, indent=2))
        
        # Log to audit system
        if hasattr(self, 'audit_logger'):
            self.audit_logger.log_security_event(
                event_type='security_error_logged',
                user_id=error_data.get('context', {}).get('user_id', 0),
                description=f"Security error logged: {error.error_code}",
                severity='error'
            )
    
    def log_error_pattern(self, pattern_type: str, occurrences: int, 
                         time_window: str, details: Optional[Dict[str, Any]] = None) -> None:
        """Log security error patterns for analysis"""
        
        pattern_data = {
            'pattern_type': pattern_type,
            'occurrences': occurrences,
            'time_window': time_window,
            'details': details or {},
            'timestamp': datetime.utcnow().isoformat()
        }
        
        self.logger.warning(f"Security Error Pattern Detected: {json.dumps(pattern_data)}")


class SecurityRecoveryManager:
    """Manages recovery from security errors"""
    
    def __init__(self):
        self.recovery_strategies = {
            'SEC_ERR_AUTH': self._recover_authentication,
            'SEC_ERR_SESSION': self._recover_session,
            'SEC_ERR_ENCRYPT': self._recover_encryption,
            'SEC_ERR_MFA': self._recover_mfa,
            'SEC_ERR_RATE_LIMIT': self._recover_rate_limit
        }
    
    def attempt_recovery(self, error: SecurityError, context: Dict[str, Any]) -> bool:
        """Attempt to recover from security error"""
        
        recovery_func = self.recovery_strategies.get(error.error_code)
        if recovery_func:
            try:
                return recovery_func(error, context)
            except Exception as recovery_error:
                logging.error(f"Recovery failed: {str(recovery_error)}")
                return False
        
        return False
    
    def _recover_authentication(self, error: SecurityError, context: Dict[str, Any]) -> bool:
        """Attempt authentication recovery"""
        # Implement authentication recovery logic
        return False
    
    def _recover_session(self, error: SecurityError, context: Dict[str, Any]) -> bool:
        """Attempt session recovery"""
        # Implement session recovery logic
        return False
    
    def _recover_encryption(self, error: SecurityError, context: Dict[str, Any]) -> bool:
        """Attempt encryption recovery"""
        # Implement encryption recovery logic
        return False
    
    def _recover_mfa(self, error: SecurityError, context: Dict[str, Any]) -> bool:
        """Attempt MFA recovery"""
        # Implement MFA recovery logic
        return False
    
    def _recover_rate_limit(self, error: SecurityError, context: Dict[str, Any]) -> bool:
        """Attempt rate limit recovery"""
        # Implement rate limit recovery logic
        return False


# Global instances
security_error_handler_instance = SecurityErrorHandler()
security_error_logger = SecurityErrorLogger()
security_recovery_manager = SecurityRecoveryManager()
