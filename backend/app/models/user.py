"""
User model for authentication and authorization.
"""
from datetime import datetime
from flask_sqlalchemy import SQLAlchemy
import bcrypt

from app import db

class User(db.Model):
    """User model representing healthcare providers and administrators."""
    
    __tablename__ = 'users'
    
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(128), nullable=False)
    first_name = db.Column(db.String(50), nullable=False)
    last_name = db.Column(db.String(50), nullable=False)
    role = db.Column(db.String(20), nullable=False, default='provider')
    is_active = db.Column(db.Boolean, default=True, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    last_login = db.Column(db.DateTime)
    otp_secret = db.Column(db.String(32))
    
    def set_password(self, password):
        """Hash and set the user password."""
        self.password_hash = bcrypt.hashpw(
            password.encode('utf-8'), 
            bcrypt.gensalt()
        ).decode('utf-8')
    
    def check_password(self, password):
        """Check if the provided password matches the stored hash."""
        return bcrypt.checkpw(
            password.encode('utf-8'),
            self.password_hash.encode('utf-8')
        )
    
    def __repr__(self):
        return f'<User {self.email}>'