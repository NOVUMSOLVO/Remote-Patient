"""
Patient model for remote monitoring system.
"""
from datetime import datetime
from app import db


class Patient(db.Model):
    """Patient model representing individuals being monitored."""
    
    __tablename__ = 'patients'
    
    id = db.Column(db.Integer, primary_key=True)
    first_name = db.Column(db.String(50), nullable=False)
    last_name = db.Column(db.String(50), nullable=False)
    date_of_birth = db.Column(db.Date, nullable=False)
    gender = db.Column(db.String(10), nullable=False)
    email = db.Column(db.String(120), unique=True)
    phone = db.Column(db.String(20))
    address = db.Column(db.String(200))
    emergency_contact_name = db.Column(db.String(100))
    emergency_contact_phone = db.Column(db.String(20))
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    # Relationships
    metrics = db.relationship('PatientMetric', backref='patient', lazy=True)
    
    def __repr__(self):
        return f'<Patient {self.id}: {self.first_name} {self.last_name}>'


class PatientMetric(db.Model):
    """Patient health metrics data model."""
    
    __tablename__ = 'patient_metrics'
    
    id = db.Column(db.Integer, primary_key=True)
    patient_id = db.Column(db.Integer, db.ForeignKey('patients.id'), nullable=False)
    metric_type = db.Column(db.String(50), nullable=False)  # e.g., heart_rate, blood_pressure, temperature
    value = db.Column(db.Float, nullable=False)
    unit = db.Column(db.String(20), nullable=False)  # e.g., bpm, mmHg, °C
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    
    def __repr__(self):
        return f'<PatientMetric {self.patient_id}: {self.metric_type} = {self.value} {self.unit}>'