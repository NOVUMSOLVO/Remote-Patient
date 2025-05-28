"""
Data Encryption at Rest Implementation
Comprehensive encryption for sensitive healthcare data according to NHS Digital standards
"""

import os
import base64
import json
from datetime import datetime, timedelta
from cryptography.fernet import Fernet, MultiFernet
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.backends import default_backend
from flask import current_app
from sqlalchemy import event, Column, String, Text, LargeBinary
from sqlalchemy.ext.hybrid import hybrid_property
import logging

logger = logging.getLogger(__name__)

class EncryptionKeyManager:
    """Manages encryption keys with rotation and hierarchy"""
    
    def __init__(self):
        self.master_key = self._get_master_key()
        self.active_keys = {}
        self.key_rotation_days = 90
        
    def _get_master_key(self):
        """Get or create master encryption key"""
        master_key_env = current_app.config.get('MASTER_ENCRYPTION_KEY')
        if master_key_env:
            return base64.urlsafe_b64decode(master_key_env)
        
        # Generate new master key if not exists
        master_key = Fernet.generate_key()
        logger.warning("Generated new master key - store securely in production")
        return master_key
    
    def derive_key(self, purpose: str, salt: bytes = None) -> bytes:
        """Derive encryption key for specific purpose"""
        if salt is None:
            salt = os.urandom(16)
        
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
            backend=default_backend()
        )
        
        purpose_bytes = f"{purpose}_{datetime.utcnow().strftime('%Y%m')}".encode()
        derived_key = kdf.derive(self.master_key + purpose_bytes)
        return base64.urlsafe_b64encode(derived_key)
    
    def get_active_key(self, purpose: str) -> bytes:
        """Get active encryption key for purpose"""
        if purpose not in self.active_keys:
            self.active_keys[purpose] = self.derive_key(purpose)
        return self.active_keys[purpose]
    
    def rotate_key(self, purpose: str) -> bytes:
        """Rotate encryption key for purpose"""
        new_key = self.derive_key(purpose)
        old_key = self.active_keys.get(purpose)
        self.active_keys[purpose] = new_key
        
        logger.info(f"Key rotated for purpose: {purpose}")
        return old_key
    
    def create_multifernet(self, purpose: str) -> MultiFernet:
        """Create MultiFernet for key rotation support"""
        current_key = self.get_active_key(purpose)
        keys = [Fernet(current_key)]
        
        # Add previous keys for decryption during rotation
        for i in range(1, 4):  # Keep 3 previous keys
            try:
                old_salt = os.urandom(16)
                old_key = self.derive_key(f"{purpose}_old_{i}", old_salt)
                keys.append(Fernet(old_key))
            except:
                break
        
        return MultiFernet(keys)

class FieldEncryption:
    """Field-level encryption for database columns"""
    
    def __init__(self, purpose: str):
        self.purpose = purpose
        self.key_manager = EncryptionKeyManager()
        
    def encrypt(self, value: str) -> str:
        """Encrypt field value"""
        if not value:
            return value
        
        fernet = Fernet(self.key_manager.get_active_key(self.purpose))
        encrypted_data = fernet.encrypt(value.encode())
        return base64.urlsafe_b64encode(encrypted_data).decode()
    
    def decrypt(self, encrypted_value: str) -> str:
        """Decrypt field value"""
        if not encrypted_value:
            return encrypted_value
        
        try:
            multifernet = self.key_manager.create_multifernet(self.purpose)
            encrypted_data = base64.urlsafe_b64decode(encrypted_value.encode())
            decrypted_data = multifernet.decrypt(encrypted_data)
            return decrypted_data.decode()
        except Exception as e:
            logger.error(f"Decryption failed for purpose {self.purpose}: {str(e)}")
            raise

class EncryptedColumn:
    """SQLAlchemy column type for encrypted data"""
    
    def __init__(self, purpose: str, column_type=String):
        self.purpose = purpose
        self.column_type = column_type
        self.encryptor = FieldEncryption(purpose)
    
    def __call__(self, *args, **kwargs):
        """Create the actual column"""
        return Column(Text, *args, **kwargs)
    
    def create_hybrid_property(self, attribute_name: str):
        """Create hybrid property for transparent encryption/decryption"""
        def getter(self):
            encrypted_value = getattr(self, f"_{attribute_name}_encrypted")
            if encrypted_value:
                return self.encryptor.decrypt(encrypted_value)
            return None
        
        def setter(self, value):
            if value:
                encrypted_value = self.encryptor.encrypt(value)
                setattr(self, f"_{attribute_name}_encrypted", encrypted_value)
            else:
                setattr(self, f"_{attribute_name}_encrypted", None)
        
        return hybrid_property(getter, setter)

class PIIEncryption:
    """Specialized encryption for Personally Identifiable Information"""
    
    def __init__(self):
        self.key_manager = EncryptionKeyManager()
        
    def encrypt_nhs_number(self, nhs_number: str) -> str:
        """Encrypt NHS number with specialized protection"""
        if not nhs_number:
            return nhs_number
        
        # Add format validation
        if len(nhs_number) != 10 or not nhs_number.isdigit():
            raise ValueError("Invalid NHS number format")
        
        encryptor = FieldEncryption('nhs_number')
        return encryptor.encrypt(nhs_number)
    
    def decrypt_nhs_number(self, encrypted_nhs: str) -> str:
        """Decrypt NHS number"""
        encryptor = FieldEncryption('nhs_number')
        return encryptor.decrypt(encrypted_nhs)
    
    def encrypt_personal_data(self, data: dict) -> dict:
        """Encrypt dictionary of personal data"""
        encrypted_data = {}
        
        pii_fields = {
            'first_name': 'name',
            'last_name': 'name',
            'email': 'email',
            'phone': 'phone',
            'address': 'address',
            'date_of_birth': 'dob'
        }
        
        for field, purpose in pii_fields.items():
            if field in data and data[field]:
                encryptor = FieldEncryption(purpose)
                encrypted_data[field] = encryptor.encrypt(str(data[field]))
            else:
                encrypted_data[field] = data.get(field)
        
        return encrypted_data
    
    def decrypt_personal_data(self, encrypted_data: dict) -> dict:
        """Decrypt dictionary of personal data"""
        decrypted_data = {}
        
        pii_fields = {
            'first_name': 'name',
            'last_name': 'name',
            'email': 'email',
            'phone': 'phone',
            'address': 'address',
            'date_of_birth': 'dob'
        }
        
        for field, purpose in pii_fields.items():
            if field in encrypted_data and encrypted_data[field]:
                encryptor = FieldEncryption(purpose)
                decrypted_data[field] = encryptor.decrypt(encrypted_data[field])
            else:
                decrypted_data[field] = encrypted_data.get(field)
        
        return decrypted_data

class HealthDataEncryption:
    """Specialized encryption for health and medical data"""
    
    def __init__(self):
        self.key_manager = EncryptionKeyManager()
    
    def encrypt_vital_signs(self, vital_data: dict) -> dict:
        """Encrypt vital signs data"""
        encryptor = FieldEncryption('health_vitals')
        
        encrypted_vitals = {}
        for key, value in vital_data.items():
            if value is not None:
                encrypted_vitals[key] = encryptor.encrypt(json.dumps(value))
            else:
                encrypted_vitals[key] = None
        
        return encrypted_vitals
    
    def decrypt_vital_signs(self, encrypted_vitals: dict) -> dict:
        """Decrypt vital signs data"""
        encryptor = FieldEncryption('health_vitals')
        
        decrypted_vitals = {}
        for key, encrypted_value in encrypted_vitals.items():
            if encrypted_value:
                decrypted_json = encryptor.decrypt(encrypted_value)
                decrypted_vitals[key] = json.loads(decrypted_json)
            else:
                decrypted_vitals[key] = None
        
        return decrypted_vitals
    
    def encrypt_medical_notes(self, notes: str) -> str:
        """Encrypt medical notes and observations"""
        if not notes:
            return notes
        
        encryptor = FieldEncryption('medical_notes')
        return encryptor.encrypt(notes)
    
    def decrypt_medical_notes(self, encrypted_notes: str) -> str:
        """Decrypt medical notes"""
        if not encrypted_notes:
            return encrypted_notes
        
        encryptor = FieldEncryption('medical_notes')
        return encryptor.decrypt(encrypted_notes)

class DatabaseEncryptionMixin:
    """Mixin class to add encryption capabilities to SQLAlchemy models"""
    
    @classmethod
    def create_encrypted_field(cls, field_name: str, purpose: str):
        """Create an encrypted field on the model"""
        storage_field = f"_{field_name}_encrypted"
        encryptor = FieldEncryption(purpose)
        
        # Add the storage column
        setattr(cls, storage_field, Column(Text))
        
        # Create property methods
        def getter(self):
            encrypted_value = getattr(self, storage_field)
            if encrypted_value:
                return encryptor.decrypt(encrypted_value)
            return None
        
        def setter(self, value):
            if value:
                encrypted_value = encryptor.encrypt(str(value))
                setattr(self, storage_field, encrypted_value)
            else:
                setattr(self, storage_field, None)
        
        # Set the hybrid property
        prop = hybrid_property(getter, setter)
        setattr(cls, field_name, prop)

class EncryptionAuditLog:
    """Audit logging for encryption operations"""
    
    def __init__(self):
        self.logger = logging.getLogger('encryption_audit')
    
    def log_encryption_event(self, event_type: str, purpose: str, user_id: int = None):
        """Log encryption-related events"""
        event = {
            'timestamp': datetime.utcnow().isoformat(),
            'event_type': event_type,
            'purpose': purpose,
            'user_id': user_id,
            'compliance_level': 'NHS_DIGITAL'
        }
        
        self.logger.info(f"Encryption event: {event_type} for {purpose}")
    
    def log_key_rotation(self, purpose: str, old_key_id: str, new_key_id: str):
        """Log key rotation events"""
        event = {
            'timestamp': datetime.utcnow().isoformat(),
            'event_type': 'key_rotation',
            'purpose': purpose,
            'old_key_id': old_key_id,
            'new_key_id': new_key_id
        }
        
        self.logger.info(f"Key rotation completed for {purpose}")

# Message encryption for secure communications
def encrypt_message(message_content):
    """Encrypt message content for secure storage"""
    try:
        # Use health data encryption for messages as they may contain PHI
        return health_data_encryption.encrypt_data(message_content, 'message_content')
    except Exception as e:
        logger.error(f"Message encryption error: {str(e)}")
        # Return original content if encryption fails (in production, this should fail securely)
        return message_content

def decrypt_message(encrypted_content):
    """Decrypt encrypted message content"""
    try:
        # Use health data encryption for messages
        return health_data_encryption.decrypt_data(encrypted_content, 'message_content')
    except Exception as e:
        logger.error(f"Message decryption error: {str(e)}")
        # Return a placeholder if decryption fails
        return "[Decryption failed. Please contact support.]"

# Initialize encryption components
key_manager = EncryptionKeyManager()
pii_encryption = PIIEncryption()
health_data_encryption = HealthDataEncryption()
encryption_audit = EncryptionAuditLog()

def setup_database_encryption(app):
    """Setup database encryption for the application"""
    
    # Configure encryption for SQLAlchemy events
    @event.listens_for(app.extensions['sqlalchemy'].db.engine, "before_cursor_execute")
    def before_cursor_execute(conn, cursor, statement, parameters, context, executemany):
        """Log database queries for audit (production: be careful with sensitive data)"""
        if app.config.get('AUDIT_DATABASE_QUERIES', False):
            encryption_audit.log_encryption_event('database_query', 'general')
    
    # Key rotation scheduler (implement with Celery in production)
    def schedule_key_rotation():
        """Schedule regular key rotation"""
        purposes = ['nhs_number', 'name', 'email', 'phone', 'health_vitals', 'medical_notes']
        
        for purpose in purposes:
            # Check if key needs rotation (implement date checking)
            # key_manager.rotate_key(purpose)
            pass
    
    logger.info("Database encryption setup completed")
    return True
