"""
Middleware package for Remote Patient Monitoring system
Contains security, authentication, and request processing middleware
"""

from .security import (
    security_middleware,
    apply_security_headers,
    require_mfa,
    require_admin,
    require_healthcare_professional,
    require_secure_connection,
    validate_data_classification,
    audit_data_access,
    encrypt_sensitive_data,
    decrypt_sensitive_data
)

__all__ = [
    'security_middleware',
    'apply_security_headers',
    'require_mfa',
    'require_admin',
    'require_healthcare_professional',
    'require_secure_connection',
    'validate_data_classification',
    'audit_data_access',
    'encrypt_sensitive_data',
    'decrypt_sensitive_data'
]
