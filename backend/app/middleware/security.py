"""
Security middleware for the Remote Patient Monitoring system
Implements NHS Digital security standards and best practices
"""

from flask import request, jsonify, g, current_app
from functools import wraps
from app.utils.security import SecurityManager, RateLimiter, IPWhitelistManager, AuditLogger, SessionManager, MFAManager
from app.utils.ddos_protection import DDoSProtection
from app.utils.validation import SecurityValidator
from app.utils.security_monitor import SecurityMonitor
from app.models import User, SecurityAuditLog
from app import db
import jwt
from datetime import datetime, timedelta
import ipaddress
import re

# Initialize security managers for Phase 1 compliance
security_manager = SecurityManager()
rate_limiter = RateLimiter()
ip_whitelist_manager = IPWhitelistManager()
audit_logger = AuditLogger()
session_manager = SessionManager()
mfa_manager = MFAManager()
ddos_protection = DDoSProtection()
security_validator = SecurityValidator()
security_monitor = SecurityMonitor()

# Security headers for NHS Digital compliance
SECURITY_HEADERS = {
    'X-Content-Type-Options': 'nosniff',
    'X-Frame-Options': 'DENY',
    'X-XSS-Protection': '1; mode=block',
    'Strict-Transport-Security': 'max-age=31536000; includeSubDomains',
    'Content-Security-Policy': "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; img-src 'self' data: https:; connect-src 'self'; font-src 'self'",
    'Referrer-Policy': 'strict-origin-when-cross-origin',
    'Permissions-Policy': 'geolocation=(), microphone=(), camera=()'
}

def apply_security_headers(response):
    """Apply security headers to all responses"""
    for header, value in SECURITY_HEADERS.items():
        response.headers[header] = value
    return response

def validate_request_security():
    """Validate incoming request for security compliance"""
    
    # Check content type for POST/PUT requests
    if request.method in ['POST', 'PUT', 'PATCH']:
        if not request.is_json and request.content_type != 'application/json':
            return jsonify({'error': 'Content-Type must be application/json'}), 400
    
    # Check for common attack patterns in request
    suspicious_patterns = [
        r'<script[^>]*>.*?</script>',  # XSS
        r'union\s+select',  # SQL injection
        r'drop\s+table',  # SQL injection
        r'exec\s*\(',  # Code injection
        r'eval\s*\(',  # Code injection
    ]
    
    request_data = str(request.get_data())
    for pattern in suspicious_patterns:
        if re.search(pattern, request_data, re.IGNORECASE):
            audit_logger.log_security_event(
                event_type='suspicious_request',
                user_id=getattr(g, 'current_user_id', None),
                ip_address=request.remote_addr,
                details=f'Suspicious pattern detected: {pattern}'
            )
            return jsonify({'error': 'Request blocked for security reasons'}), 403
    
    return None

def rate_limit_check():
    """Check rate limiting for the current request"""
    endpoint = request.endpoint or 'unknown'
    client_ip = request.remote_addr
    
    # Different limits for different endpoints
    limits = {
        'auth.login': {'requests': 5, 'window': 300},  # 5 attempts per 5 minutes
        'auth.register': {'requests': 3, 'window': 3600},  # 3 registrations per hour
        'auth.reset_password': {'requests': 3, 'window': 3600},  # 3 resets per hour
        'default': {'requests': 100, 'window': 60}  # 100 requests per minute
    }
    
    limit_config = limits.get(endpoint, limits['default'])
    
    if not rate_limiter.check_rate_limit(
        f"{client_ip}:{endpoint}",
        limit_config['requests'],
        limit_config['window']
    ):
        audit_logger.log_security_event(
            event_type='rate_limit_exceeded',
            user_id=getattr(g, 'current_user_id', None),
            ip_address=client_ip,
            details=f'Rate limit exceeded for endpoint: {endpoint}'
        )
        return jsonify({'error': 'Rate limit exceeded'}), 429
    
    return None

def ip_whitelist_check():
    """Check if IP is whitelisted for sensitive operations"""
    if not current_app.config.get('ENABLE_IP_WHITELIST', False):
        return None
    
    client_ip = request.remote_addr
    sensitive_endpoints = [
        'admin.',
        'auth.setup_mfa',
        'auth.disable_mfa'
    ]
    
    endpoint = request.endpoint or ''
    is_sensitive = any(endpoint.startswith(prefix) for prefix in sensitive_endpoints)
    
    if is_sensitive and not ip_whitelist_manager.is_whitelisted(client_ip):
        audit_logger.log_security_event(
            event_type='unauthorized_ip_access',
            user_id=getattr(g, 'current_user_id', None),
            ip_address=client_ip,
            details=f'Non-whitelisted IP attempted to access: {endpoint}'
        )
        return jsonify({'error': 'Access denied from this IP address'}), 403
    
    return None

def session_validation():
    """Validate user session and token"""
    if request.endpoint in ['auth.login', 'auth.register', 'health_check']:
        return None
    
    auth_header = request.headers.get('Authorization')
    if not auth_header:
        return None  # Let JWT middleware handle this
    
    try:
        token = auth_header.split(' ')[1] if ' ' in auth_header else auth_header
        payload = jwt.decode(
            token, 
            current_app.config['SECRET_KEY'], 
            algorithms=['HS256']
        )
        
        user_id = payload.get('user_id')
        if not user_id:
            return jsonify({'error': 'Invalid token'}), 401
        
        user = User.query.get(user_id)
        if not user:
            return jsonify({'error': 'User not found'}), 401
        
        # Check if account is locked
        if user.account_locked_until and user.account_locked_until > datetime.utcnow():
            return jsonify({'error': 'Account is locked'}), 403
        
        # Check session validity
        if user.session_expires and user.session_expires < datetime.utcnow():
            return jsonify({'error': 'Session expired'}), 401
        
        # Store user context
        g.current_user = user
        g.current_user_id = user.id
        
        # Update last activity
        user.last_activity = datetime.utcnow()
        db.session.commit()
        
    except jwt.ExpiredSignatureError:
        return jsonify({'error': 'Token expired'}), 401
    except jwt.InvalidTokenError:
        return jsonify({'error': 'Invalid token'}), 401
    except Exception as e:
        current_app.logger.error(f'Session validation error: {str(e)}')
        return jsonify({'error': 'Authentication error'}), 401
    
    return None

def security_middleware():
    """Main security middleware function"""
    
    # Skip security checks for health endpoint
    if request.endpoint == 'health_check':
        return None
    
    # Apply security validations
    checks = [
        validate_request_security,
        rate_limit_check,
        ip_whitelist_check,
        session_validation
    ]
    
    for check in checks:
        result = check()
        if result:
            return result
    
    return None

# Decorator for endpoints requiring MFA
def require_mfa(f):
    """Decorator to require MFA for sensitive operations"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not hasattr(g, 'current_user') or not g.current_user:
            return jsonify({'error': 'Authentication required'}), 401
        
        if not g.current_user.mfa_enabled:
            return jsonify({'error': 'MFA required for this operation'}), 403
        
        # Check if MFA was verified in this session
        mfa_verified = request.headers.get('X-MFA-Verified')
        if not mfa_verified:
            return jsonify({'error': 'MFA verification required'}), 403
        
        return f(*args, **kwargs)
    return decorated_function

# Decorator for admin-only endpoints
def require_admin(f):
    """Decorator to require admin role"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not hasattr(g, 'current_user') or not g.current_user:
            return jsonify({'error': 'Authentication required'}), 401
        
        if g.current_user.role != 'admin':
            audit_logger.log_security_event(
                event_type='unauthorized_admin_access',
                user_id=g.current_user.id,
                ip_address=request.remote_addr,
                details=f'Non-admin user attempted to access: {request.endpoint}'
            )
            return jsonify({'error': 'Admin access required'}), 403
        
        return f(*args, **kwargs)
    return decorated_function

# Decorator for healthcare professional endpoints
def require_healthcare_professional(f):
    """Decorator to require healthcare professional role"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not hasattr(g, 'current_user') or not g.current_user:
            return jsonify({'error': 'Authentication required'}), 401
        
        allowed_roles = ['doctor', 'nurse', 'admin']
        if g.current_user.role not in allowed_roles:
            audit_logger.log_security_event(
                event_type='unauthorized_healthcare_access',
                user_id=g.current_user.id,
                ip_address=request.remote_addr,
                details=f'Non-healthcare user attempted to access: {request.endpoint}'
            )
            return jsonify({'error': 'Healthcare professional access required'}), 403
        
        return f(*args, **kwargs)
    return decorated_function

def encrypt_sensitive_data(data, data_type='general'):
    """Encrypt sensitive data before storage"""
    return security_manager.encrypt_data(data, data_type)

def decrypt_sensitive_data(encrypted_data, data_type='general'):
    """Decrypt sensitive data after retrieval"""
    return security_manager.decrypt_data(encrypted_data, data_type)
