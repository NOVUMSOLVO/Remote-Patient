"""
Database Models for Remote Patient Monitoring Application
"""

from datetime import datetime, timezone, timedelta
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from app import db
import enum

class UserRole(enum.Enum):
    """User roles enumeration"""
    PATIENT = "patient"
    DOCTOR = "doctor"
    NURSE = "nurse"
    ADMIN = "admin"
    CAREGIVER = "caregiver"

class AlertSeverity(enum.Enum):
    """Alert severity levels"""
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

class DeviceType(enum.Enum):
    """Device types enumeration"""
    BLOOD_PRESSURE = "blood_pressure"
    GLUCOSE_METER = "glucose_meter"
    HEART_RATE = "heart_rate"
    WEIGHT_SCALE = "weight_scale"
    THERMOMETER = "thermometer"
    PULSE_OXIMETER = "pulse_oximeter"
    SMARTWATCH = "smartwatch"

class User(db.Model):
    """User model for all system users"""
    __tablename__ = 'users'
    
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(120), unique=True, nullable=False, index=True)
    password_hash = db.Column(db.String(255), nullable=False)
    first_name = db.Column(db.String(50), nullable=False)
    last_name = db.Column(db.String(50), nullable=False)
    phone = db.Column(db.String(20))
    role = db.Column(db.Enum(UserRole), nullable=False, default=UserRole.PATIENT)
    is_active = db.Column(db.Boolean, default=True, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    last_login = db.Column(db.DateTime)
    
    # NHS-specific fields
    nhs_number = db.Column(db.String(10), unique=True, index=True)
    gp_practice_code = db.Column(db.String(10))
    
    # Security and MFA fields
    mfa_enabled = db.Column(db.Boolean, default=False, nullable=False)
    mfa_secret = db.Column(db.String(255))  # Encrypted TOTP secret
    mfa_backup_codes = db.Column(db.Text)   # Encrypted backup codes
    password_reset_token = db.Column(db.String(255))
    password_reset_expires = db.Column(db.DateTime)
    failed_login_attempts = db.Column(db.Integer, default=0)
    account_locked_until = db.Column(db.DateTime)
    session_token = db.Column(db.String(255))
    session_expires = db.Column(db.DateTime)
    
    # Audit fields
    password_changed_at = db.Column(db.DateTime)
    last_password_reminder = db.Column(db.DateTime)
    login_count = db.Column(db.Integer, default=0)
    ip_address = db.Column(db.String(45))  # Support IPv6
    
    # Relationships
    patient_profile = db.relationship('PatientProfile', backref='user', uselist=False, cascade='all, delete-orphan')
    healthcare_provider = db.relationship('HealthcareProvider', backref='user', uselist=False, cascade='all, delete-orphan')
    
    def set_password(self, password):
        """Set password hash"""
        self.password_hash = generate_password_hash(password)
    
    def check_password(self, password):
        """Check password against hash"""
        return check_password_hash(self.password_hash, password)
    
    def is_account_locked(self):
        """Check if account is locked"""
        if self.account_locked_until:
            return datetime.utcnow() < self.account_locked_until
        return False
    
    def lock_account(self, duration_minutes=30):
        """Lock account for specified duration"""
        self.account_locked_until = datetime.utcnow() + timedelta(minutes=duration_minutes)
        self.failed_login_attempts = 0
    
    def unlock_account(self):
        """Unlock account"""
        self.account_locked_until = None
        self.failed_login_attempts = 0
    
    def increment_failed_login(self):
        """Increment failed login attempts"""
        self.failed_login_attempts = (self.failed_login_attempts or 0) + 1
        
    def reset_failed_login(self):
        """Reset failed login attempts"""
        self.failed_login_attempts = 0
        
    def update_login_info(self, ip_address):
        """Update login information"""
        self.last_login = datetime.utcnow()
        self.ip_address = ip_address
        self.login_count = (self.login_count or 0) + 1
        self.reset_failed_login()
    
    def has_valid_session(self):
        """Check if user has valid session"""
        if self.session_expires:
            return datetime.utcnow() < self.session_expires
        return False
    
    def invalidate_session(self):
        """Invalidate current session"""
        self.session_token = None
        self.session_expires = None
    
    def to_dict(self):
        """Convert to dictionary"""
        return {
            'id': self.id,
            'email': self.email,
            'first_name': self.first_name,
            'last_name': self.last_name,
            'phone': self.phone,
            'role': self.role.value,
            'is_active': self.is_active,
            'nhs_number': self.nhs_number,
            'created_at': self.created_at.isoformat() if self.created_at else None
        }

class PatientProfile(db.Model):
    """Extended patient profile"""
    __tablename__ = 'patient_profiles'
    
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    date_of_birth = db.Column(db.Date)
    gender = db.Column(db.String(10))
    height = db.Column(db.Float)  # in cm
    weight = db.Column(db.Float)  # in kg
    blood_type = db.Column(db.String(5))
    emergency_contact_name = db.Column(db.String(100))
    emergency_contact_phone = db.Column(db.String(20))
    medical_conditions = db.Column(db.Text)
    medications = db.Column(db.Text)
    allergies = db.Column(db.Text)
    care_plan = db.Column(db.Text)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    # Relationships
    devices = db.relationship('Device', backref='patient', cascade='all, delete-orphan')
    health_records = db.relationship('HealthRecord', backref='patient', cascade='all, delete-orphan')
    alerts = db.relationship('Alert', backref='patient', cascade='all, delete-orphan')

class HealthcareProvider(db.Model):
    """Healthcare provider profile"""
    __tablename__ = 'healthcare_providers'
    
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    license_number = db.Column(db.String(50))
    specialization = db.Column(db.String(100))
    department = db.Column(db.String(100))
    hospital_name = db.Column(db.String(200))
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

class Device(db.Model):
    """Medical devices"""
    __tablename__ = 'devices'
    
    id = db.Column(db.Integer, primary_key=True)
    patient_id = db.Column(db.Integer, db.ForeignKey('patient_profiles.id'), nullable=False)
    device_name = db.Column(db.String(100), nullable=False)
    device_type = db.Column(db.Enum(DeviceType), nullable=False)
    device_id = db.Column(db.String(100), unique=True, nullable=False)
    manufacturer = db.Column(db.String(100))
    model = db.Column(db.String(100))
    firmware_version = db.Column(db.String(50))
    is_active = db.Column(db.Boolean, default=True)
    last_sync = db.Column(db.DateTime)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    # Relationships
    health_records = db.relationship('HealthRecord', backref='device', cascade='all, delete-orphan')

class HealthRecord(db.Model):
    """Health data records"""
    __tablename__ = 'health_records'
    
    id = db.Column(db.Integer, primary_key=True)
    patient_id = db.Column(db.Integer, db.ForeignKey('patient_profiles.id'), nullable=False)
    device_id = db.Column(db.Integer, db.ForeignKey('devices.id'))
    record_type = db.Column(db.String(50), nullable=False)  # blood_pressure, glucose, etc.
    value = db.Column(db.JSON, nullable=False)  # Flexible JSON field for different data types
    unit = db.Column(db.String(20))
    timestamp = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    notes = db.Column(db.Text)
    is_validated = db.Column(db.Boolean, default=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

class Alert(db.Model):
    """Alerts and notifications"""
    __tablename__ = 'alerts'
    
    id = db.Column(db.Integer, primary_key=True)
    patient_id = db.Column(db.Integer, db.ForeignKey('patient_profiles.id'), nullable=False)
    health_record_id = db.Column(db.Integer, db.ForeignKey('health_records.id'))
    alert_type = db.Column(db.String(50), nullable=False)
    severity = db.Column(db.Enum(AlertSeverity), nullable=False)
    title = db.Column(db.String(200), nullable=False)
    message = db.Column(db.Text, nullable=False)
    is_read = db.Column(db.Boolean, default=False)
    is_resolved = db.Column(db.Boolean, default=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    resolved_at = db.Column(db.DateTime)
    resolved_by = db.Column(db.Integer, db.ForeignKey('users.id'))

class Appointment(db.Model):
    """Appointments and consultations"""
    __tablename__ = 'appointments'
    
    id = db.Column(db.Integer, primary_key=True)
    patient_id = db.Column(db.Integer, db.ForeignKey('patient_profiles.id'), nullable=False)
    provider_id = db.Column(db.Integer, db.ForeignKey('healthcare_providers.id'), nullable=False)
    appointment_type = db.Column(db.String(50), nullable=False)  # video, phone, in-person
    scheduled_time = db.Column(db.DateTime, nullable=False)
    duration = db.Column(db.Integer, default=30)  # minutes
    status = db.Column(db.String(20), default='scheduled')  # scheduled, completed, cancelled
    notes = db.Column(db.Text)
    video_link = db.Column(db.String(500))
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

class Message(db.Model):
    """Secure messaging"""
    __tablename__ = 'messages'
    
    id = db.Column(db.Integer, primary_key=True)
    sender_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    recipient_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    subject = db.Column(db.String(200))
    content = db.Column(db.Text, nullable=False)
    is_read = db.Column(db.Boolean, default=False)
    is_encrypted = db.Column(db.Boolean, default=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    read_at = db.Column(db.DateTime)
    
    # Relationships
    sender = db.relationship('User', foreign_keys=[sender_id], backref='sent_messages')
    recipient = db.relationship('User', foreign_keys=[recipient_id], backref='received_messages')

class Report(db.Model):
    """Generated reports"""
    __tablename__ = 'reports'
    
    id = db.Column(db.Integer, primary_key=True)
    generated_by = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    report_type = db.Column(db.String(50), nullable=False)
    title = db.Column(db.String(200), nullable=False)
    parameters = db.Column(db.JSON)  # Report parameters
    file_path = db.Column(db.String(500))
    status = db.Column(db.String(20), default='generating')  # generating, completed, failed

class SecurityAuditLog(db.Model):
    """Security audit log for tracking security events"""
    __tablename__ = 'security_audit_logs'
    
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'))
    event_type = db.Column(db.String(50), nullable=False)  # login, logout, mfa_setup, password_change, etc.
    event_status = db.Column(db.String(20), nullable=False)  # success, failure, warning
    ip_address = db.Column(db.String(45))  # IPv6 support
    user_agent = db.Column(db.String(500))
    session_id = db.Column(db.String(255))
    details = db.Column(db.JSON)  # Additional event details
    risk_score = db.Column(db.Integer, default=0)  # 0-100 risk assessment
    location = db.Column(db.String(100))  # Geographical location if available
    timestamp = db.Column(db.DateTime, default=datetime.utcnow, nullable=False, index=True)
    
    # Relationships
    user = db.relationship('User', backref='security_logs')
    
    def to_dict(self):
        """Convert to dictionary"""
        return {
            'id': self.id,
            'user_id': self.user_id,
            'event_type': self.event_type,
            'event_status': self.event_status,
            'ip_address': self.ip_address,
            'timestamp': self.timestamp.isoformat() if self.timestamp else None,
            'details': self.details,
            'risk_score': self.risk_score
        }

class UserSession(db.Model):
    """Active user sessions for session management"""
    __tablename__ = 'user_sessions'
    
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    session_token = db.Column(db.String(255), unique=True, nullable=False, index=True)
    ip_address = db.Column(db.String(45))
    user_agent = db.Column(db.String(500))
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    expires_at = db.Column(db.DateTime, nullable=False)
    last_activity = db.Column(db.DateTime, default=datetime.utcnow)
    is_active = db.Column(db.Boolean, default=True)
    
    # Relationships
    user = db.relationship('User', backref='sessions')
    
    def is_expired(self):
        """Check if session is expired"""
        return datetime.utcnow() > self.expires_at
    
    def is_valid(self):
        """Check if session is valid"""
        return self.is_active and not self.is_expired()
    
    def refresh(self, duration_hours=24):
        """Refresh session expiration"""
        self.expires_at = datetime.utcnow() + timedelta(hours=duration_hours)
        self.last_activity = datetime.utcnow()
    
    def invalidate(self):
        """Invalidate session"""
        self.is_active = False

class DataEncryption(db.Model):
    """Data encryption metadata for tracking encrypted fields"""
    __tablename__ = 'data_encryption'
    
    id = db.Column(db.Integer, primary_key=True)
    table_name = db.Column(db.String(100), nullable=False)
    field_name = db.Column(db.String(100), nullable=False)
    record_id = db.Column(db.Integer, nullable=False)
    encryption_key_id = db.Column(db.String(100), nullable=False)
    encryption_algorithm = db.Column(db.String(50), default='Fernet')
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    def to_dict(self):
        """Convert to dictionary"""
        return {
            'id': self.id,
            'table_name': self.table_name,
            'field_name': self.field_name,
            'record_id': self.record_id,
            'encryption_algorithm': self.encryption_algorithm,
            'created_at': self.created_at.isoformat() if self.created_at else None
        }
