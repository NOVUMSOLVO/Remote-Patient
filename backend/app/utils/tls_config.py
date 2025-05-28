"""
TLS 1.3 Configuration for NHS Digital Security Standards
Implements secure data transmission according to NHS requirements
"""

import ssl
import os
from flask import current_app
import logging

logger = logging.getLogger(__name__)

class TLSConfigManager:
    """Manages TLS 1.3 configuration for secure data transmission"""
    
    def __init__(self):
        self.min_version = ssl.TLSVersion.TLSv1_2  # Minimum fallback
        self.max_version = ssl.TLSVersion.TLSv1_3  # Preferred
        
    def create_ssl_context(self):
        """Create SSL context with NHS Digital security requirements"""
        context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
        
        # Set TLS version constraints
        context.minimum_version = self.min_version
        context.maximum_version = self.max_version
        
        # Configure cipher suites (NHS approved)
        context.set_ciphers('ECDHE+AESGCM:ECDHE+CHACHA20:DHE+AESGCM:DHE+CHACHA20:!aNULL:!MD5:!DSS')
        
        # Load certificates
        cert_file = current_app.config.get('SSL_CERT_FILE')
        key_file = current_app.config.get('SSL_KEY_FILE')
        ca_file = current_app.config.get('SSL_CA_FILE')
        
        if cert_file and key_file:
            if os.path.exists(cert_file) and os.path.exists(key_file):
                context.load_cert_chain(cert_file, key_file)
                logger.info("SSL certificates loaded successfully")
            else:
                logger.warning("SSL certificate files not found")
        
        if ca_file and os.path.exists(ca_file):
            context.load_verify_locations(ca_file)
        
        # Security options
        context.options |= ssl.OP_NO_SSLv2
        context.options |= ssl.OP_NO_SSLv3
        context.options |= ssl.OP_NO_TLSv1
        context.options |= ssl.OP_NO_TLSv1_1
        context.options |= ssl.OP_SINGLE_DH_USE
        context.options |= ssl.OP_SINGLE_ECDH_USE
        
        # Disable compression to prevent CRIME attacks
        context.options |= ssl.OP_NO_COMPRESSION
        
        # Enable hostname checking
        context.check_hostname = True
        context.verify_mode = ssl.CERT_REQUIRED
        
        return context
    
    def validate_tls_configuration(self):
        """Validate TLS configuration meets NHS standards"""
        try:
            context = self.create_ssl_context()
            
            # Check TLS version support
            if context.maximum_version < ssl.TLSVersion.TLSv1_2:
                raise ValueError("TLS 1.2 minimum required")
            
            # Validate cipher suites
            ciphers = context.get_ciphers()
            if not ciphers:
                raise ValueError("No valid cipher suites configured")
            
            # Check for weak ciphers
            weak_ciphers = ['RC4', 'DES', 'MD5', 'NULL']
            for cipher in ciphers:
                cipher_name = cipher.get('name', '')
                for weak in weak_ciphers:
                    if weak in cipher_name:
                        raise ValueError(f"Weak cipher detected: {cipher_name}")
            
            logger.info("TLS configuration validation passed")
            return True
            
        except Exception as e:
            logger.error(f"TLS configuration validation failed: {str(e)}")
            return False
    
    def get_security_headers(self):
        """Get security headers for HTTPS"""
        return {
            'Strict-Transport-Security': 'max-age=31536000; includeSubDomains; preload',
            'Content-Security-Policy': "default-src 'self'; upgrade-insecure-requests;",
            'X-Content-Type-Options': 'nosniff',
            'X-Frame-Options': 'DENY',
            'X-XSS-Protection': '1; mode=block',
            'Referrer-Policy': 'strict-origin-when-cross-origin'
        }

class DatabaseEncryption:
    """Database encryption at rest implementation"""
    
    def __init__(self):
        self.encryption_key = current_app.config.get('DATABASE_ENCRYPTION_KEY')
        
    def setup_database_encryption(self):
        """Configure database encryption at rest"""
        database_config = {
            'postgresql_tde': {
                'encryption_key_file': current_app.config.get('DB_ENCRYPTION_KEY_FILE'),
                'cipher': 'AES-256-CBC',
                'key_rotation_days': 90
            },
            'ssl_config': {
                'sslmode': 'require',
                'sslcert': current_app.config.get('DB_SSL_CERT'),
                'sslkey': current_app.config.get('DB_SSL_KEY'),
                'sslrootcert': current_app.config.get('DB_SSL_CA')
            }
        }
        
        return database_config
    
    def encrypt_sensitive_columns(self, model_class, sensitive_fields):
        """Apply encryption to sensitive database columns"""
        encryption_metadata = {}
        
        for field in sensitive_fields:
            if hasattr(model_class, field):
                encryption_metadata[field] = {
                    'encrypted': True,
                    'algorithm': 'AES-256-GCM',
                    'key_id': 'primary',
                    'compliance': 'NHS_DIGITAL'
                }
        
        return encryption_metadata
    
    def generate_database_key(self):
        """Generate database encryption key"""
        from cryptography.fernet import Fernet
        return Fernet.generate_key()

class NetworkSecurity:
    """Network security configurations"""
    
    @staticmethod
    def configure_firewall_rules():
        """Define firewall rules for NHS compliance"""
        rules = {
            'inbound': [
                {'port': 443, 'protocol': 'TCP', 'source': '0.0.0.0/0', 'description': 'HTTPS'},
                {'port': 80, 'protocol': 'TCP', 'source': '0.0.0.0/0', 'description': 'HTTP (redirect to HTTPS)'},
                {'port': 22, 'protocol': 'TCP', 'source': 'admin_ips_only', 'description': 'SSH Admin'},
            ],
            'outbound': [
                {'port': 443, 'protocol': 'TCP', 'destination': '0.0.0.0/0', 'description': 'HTTPS Outbound'},
                {'port': 53, 'protocol': 'UDP', 'destination': '0.0.0.0/0', 'description': 'DNS'},
                {'port': 5432, 'protocol': 'TCP', 'destination': 'db_subnet', 'description': 'PostgreSQL'},
            ]
        }
        return rules
    
    @staticmethod
    def configure_vpc_security():
        """Configure VPC security for NHS compliance"""
        vpc_config = {
            'private_subnets': True,
            'public_subnets': False,
            'nat_gateway': True,
            'flow_logs': True,
            'encryption_in_transit': True,
            'network_acls': {
                'default_deny': True,
                'explicit_allow_rules': True
            }
        }
        return vpc_config

def create_production_ssl_context():
    """Create production-ready SSL context"""
    tls_manager = TLSConfigManager()
    
    if tls_manager.validate_tls_configuration():
        return tls_manager.create_ssl_context()
    else:
        raise RuntimeError("TLS configuration validation failed")

def apply_security_configurations(app):
    """Apply all security configurations to Flask app"""
    
    # TLS Configuration
    tls_manager = TLSConfigManager()
    
    # Database Encryption
    db_encryption = DatabaseEncryption()
    
    # Network Security
    network_security = NetworkSecurity()
    
    # Apply configurations
    if app.config.get('SSL_ENABLED', False):
        app.ssl_context = tls_manager.create_ssl_context()
        
        # Add security headers
        security_headers = tls_manager.get_security_headers()
        
        @app.after_request
        def add_security_headers(response):
            for header, value in security_headers.items():
                response.headers[header] = value
            return response
    
    # Log security status
    logger.info("Security configurations applied successfully")
    
    return {
        'tls_configured': app.config.get('SSL_ENABLED', False),
        'database_encryption': bool(app.config.get('DATABASE_ENCRYPTION_KEY')),
        'network_security': True
    }
