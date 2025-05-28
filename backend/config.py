"""
Remote Patient Monitoring (RPM) Application
Flask Backend Configuration
"""

import os
from datetime import timedelta
from cryptography.fernet import Fernet

class Config:
    """Base configuration class"""
    
    # Basic Flask configuration
    SECRET_KEY = os.environ.get('SECRET_KEY') or 'dev-secret-key-change-in-production'
    
    # Database configuration
    SQLALCHEMY_DATABASE_URI = os.environ.get('DATABASE_URL') or \
        'sqlite:///rpm_development.db'
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    
    # JWT configuration
    JWT_SECRET_KEY = os.environ.get('JWT_SECRET_KEY') or 'jwt-secret-change-in-production'
    JWT_ACCESS_TOKEN_EXPIRES = timedelta(hours=1)
    JWT_REFRESH_TOKEN_EXPIRES = timedelta(days=30)
    
    # Mail configuration
    MAIL_SERVER = os.environ.get('MAIL_SERVER')
    MAIL_PORT = int(os.environ.get('MAIL_PORT') or 587)
    MAIL_USE_TLS = os.environ.get('MAIL_USE_TLS', 'true').lower() in ['true', 'on', '1']
    MAIL_USERNAME = os.environ.get('MAIL_USERNAME')
    MAIL_PASSWORD = os.environ.get('MAIL_PASSWORD')
    
    # File upload configuration
    MAX_CONTENT_LENGTH = 16 * 1024 * 1024  # 16MB max file size
    UPLOAD_FOLDER = 'uploads'
    
    # CORS configuration
    CORS_HEADERS = 'Content-Type'
    
    # NHS FHIR API configuration
    FHIR_BASE_URL = os.environ.get('FHIR_BASE_URL') or 'https://fhir.nhs.uk'
    FHIR_API_KEY = os.environ.get('FHIR_API_KEY')
    
    # Device integration configuration
    DEVICE_API_TIMEOUT = 30
    BLUETOOTH_SCAN_TIMEOUT = 10
    
    # Real-time monitoring configuration
    WEBSOCKET_URL = os.environ.get('WEBSOCKET_URL') or 'ws://localhost:5000'
    
    # Logging configuration
    LOG_LEVEL = os.environ.get('LOG_LEVEL') or 'INFO'
    
    # Security configuration
    ENCRYPTION_KEY = os.environ.get('ENCRYPTION_KEY') or Fernet.generate_key()
    SESSION_TIMEOUT_MINUTES = int(os.environ.get('SESSION_TIMEOUT_MINUTES') or 120)
    MAX_LOGIN_ATTEMPTS = int(os.environ.get('MAX_LOGIN_ATTEMPTS') or 5)
    ACCOUNT_LOCKOUT_DURATION_MINUTES = int(os.environ.get('ACCOUNT_LOCKOUT_DURATION_MINUTES') or 30)
    REQUIRE_MFA = os.environ.get('REQUIRE_MFA', 'false').lower() in ['true', 'on', '1']
    STRICT_IP_VALIDATION = os.environ.get('STRICT_IP_VALIDATION', 'false').lower() in ['true', 'on', '1']
    
    # IP Whitelist configuration (comma-separated list)
    IP_WHITELIST = os.environ.get('IP_WHITELIST', '').split(',') if os.environ.get('IP_WHITELIST') else []
    
    # Rate limiting configuration
    RATE_LIMIT_ENABLED = True
    RATE_LIMIT_DEFAULT = '100/hour'  # Default rate limit
    RATE_LIMIT_LOGIN = '5/minute'    # Login endpoint rate limit
    
    # Password policy configuration
    PASSWORD_MIN_LENGTH = 12
    PASSWORD_REQUIRE_UPPER = True
    PASSWORD_REQUIRE_LOWER = True
    PASSWORD_REQUIRE_DIGITS = True
    PASSWORD_REQUIRE_SPECIAL = True
    PASSWORD_HISTORY_COUNT = 5  # Number of previous passwords to remember
    
    # Data encryption configuration
    ENCRYPT_PII = True  # Encrypt personally identifiable information
    ENCRYPT_HEALTH_DATA = True  # Encrypt health data at rest
    
    # NHS Digital API integration security
    NHS_API_CLIENT_ID = os.environ.get('NHS_API_CLIENT_ID')
    NHS_API_CLIENT_SECRET = os.environ.get('NHS_API_CLIENT_SECRET')
    NHS_API_REDIRECT_URI = os.environ.get('NHS_API_REDIRECT_URI')
    NHS_CIS2_ENABLED = os.environ.get('NHS_CIS2_ENABLED', 'false').lower() in ['true', 'on', '1']
    
    # NHS CIS2 Authentication Configuration
    NHS_CIS2_BASE_URL = os.environ.get('NHS_CIS2_BASE_URL') or 'https://auth.login.nhs.uk'
    NHS_CIS2_CLIENT_ID = os.environ.get('NHS_CIS2_CLIENT_ID')
    NHS_CIS2_CLIENT_SECRET = os.environ.get('NHS_CIS2_CLIENT_SECRET')
    NHS_CIS2_REDIRECT_URI = os.environ.get('NHS_CIS2_REDIRECT_URI')
    NHS_CIS2_SCOPE = os.environ.get('NHS_CIS2_SCOPE') or 'openid profile smartcard'
    
    # TLS/SSL Configuration
    SSL_ENABLED = os.environ.get('SSL_ENABLED', 'false').lower() in ['true', 'on', '1']
    SSL_CERT_FILE = os.environ.get('SSL_CERT_FILE')
    SSL_KEY_FILE = os.environ.get('SSL_KEY_FILE')
    SSL_CA_FILE = os.environ.get('SSL_CA_FILE')
    TLS_MIN_VERSION = os.environ.get('TLS_MIN_VERSION') or '1.2'
    TLS_MAX_VERSION = os.environ.get('TLS_MAX_VERSION') or '1.3'
    
    # Database Encryption Configuration
    DATABASE_ENCRYPTION_KEY = os.environ.get('DATABASE_ENCRYPTION_KEY')
    MASTER_ENCRYPTION_KEY = os.environ.get('MASTER_ENCRYPTION_KEY')
    DB_ENCRYPTION_KEY_FILE = os.environ.get('DB_ENCRYPTION_KEY_FILE')
    DB_SSL_CERT = os.environ.get('DB_SSL_CERT')
    DB_SSL_KEY = os.environ.get('DB_SSL_KEY')
    DB_SSL_CA = os.environ.get('DB_SSL_CA')
    ENCRYPTION_KEY_ROTATION_DAYS = int(os.environ.get('ENCRYPTION_KEY_ROTATION_DAYS') or 90)
    
    # Security Audit Configuration
    AUDIT_DATABASE_QUERIES = os.environ.get('AUDIT_DATABASE_QUERIES', 'false').lower() in ['true', 'on', '1']
    AUDIT_FILE_ACCESS = os.environ.get('AUDIT_FILE_ACCESS', 'true').lower() in ['true', 'on', '1']
    AUDIT_DATA_CHANGES = os.environ.get('AUDIT_DATA_CHANGES', 'true').lower() in ['true', 'on', '1']
    
    # Enhanced IP Whitelist Configuration
    ENABLE_IP_WHITELIST = os.environ.get('ENABLE_IP_WHITELIST', 'false').lower() in ['true', 'on', '1']
    ADMIN_IP_WHITELIST = os.environ.get('ADMIN_IP_WHITELIST', '').split(',') if os.environ.get('ADMIN_IP_WHITELIST') else []
    
    # Session Security Configuration
    SESSION_COOKIE_SECURE = True
    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SAMESITE = 'Strict'
    PERMANENT_SESSION_LIFETIME = timedelta(minutes=SESSION_TIMEOUT_MINUTES)
    
    # Security Headers Configuration
    SECURITY_HEADERS_ENABLED = True
    CSP_POLICY = os.environ.get('CSP_POLICY') or "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; img-src 'self' data: https:; connect-src 'self'; font-src 'self'"
    
    LOG_FILE = os.environ.get('LOG_FILE') or 'rpm.log'

class DevelopmentConfig(Config):
    """Development configuration"""
    DEBUG = True
    TESTING = False

class TestingConfig(Config):
    """Testing configuration"""
    TESTING = True
    SQLALCHEMY_DATABASE_URI = 'sqlite:///:memory:'
    WTF_CSRF_ENABLED = False

class ProductionConfig(Config):
    """Production configuration with enhanced security"""
    DEBUG = False
    TESTING = False
    
    # Enhanced security for production
    SSL_ENABLED = True
    REQUIRE_MFA = True
    STRICT_IP_VALIDATION = True
    ENABLE_IP_WHITELIST = True
    
    # Encryption requirements
    ENCRYPT_PII = True
    ENCRYPT_HEALTH_DATA = True
    DATABASE_ENCRYPTION_KEY = os.environ.get('DATABASE_ENCRYPTION_KEY')
    MASTER_ENCRYPTION_KEY = os.environ.get('MASTER_ENCRYPTION_KEY')
    
    # Enhanced audit logging
    AUDIT_DATABASE_QUERIES = True
    AUDIT_FILE_ACCESS = True
    AUDIT_DATA_CHANGES = True
    
    # Stricter session configuration
    SESSION_TIMEOUT_MINUTES = 60  # 1 hour for production
    SESSION_COOKIE_SECURE = True
    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SAMESITE = 'Strict'
    
    # Stricter rate limiting
    RATE_LIMIT_DEFAULT = '50/hour'  # More restrictive
    RATE_LIMIT_LOGIN = '3/5minute'  # 3 attempts per 5 minutes
    
    # Enhanced password policy
    PASSWORD_MIN_LENGTH = 14
    PASSWORD_HISTORY_COUNT = 10
    
    # Production TLS settings
    TLS_MIN_VERSION = '1.2'
    TLS_MAX_VERSION = '1.3'
    
    # NHS CIS2 required in production
    NHS_CIS2_ENABLED = True

config = {
    'development': DevelopmentConfig,
    'testing': TestingConfig,
    'production': ProductionConfig,
    'default': DevelopmentConfig
}
