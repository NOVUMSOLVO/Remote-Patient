"""
Patient Module Routes
Handles user registration, login, profile creation and management
"""

from flask import Blueprint, request, jsonify, current_app
from flask_jwt_extended import jwt_required, get_jwt_identity, create_access_token, create_refresh_token
from werkzeug.security import check_password_hash
from datetime import datetime
import re

from app import db
from app.models import User, PatientProfile, UserRole
from app.utils.validation import validate_email, validate_password, validate_nhs_number
from app.utils.fhir_integration import create_fhir_patient, update_fhir_patient

patient_bp = Blueprint('patient', __name__)

@patient_bp.route('/register', methods=['POST'])
def register_patient():
    """Register a new patient"""
    try:
        data = request.get_json()
        
        # Validate required fields
        required_fields = ['email', 'password', 'first_name', 'last_name']
        for field in required_fields:
            if not data.get(field):
                return jsonify({'error': f'{field} is required'}), 400
        
        # Validate email format
        if not validate_email(data['email']):
            return jsonify({'error': 'Invalid email format'}), 400
        
        # Validate password strength
        password_errors = validate_password(data['password'])
        if password_errors:
            return jsonify({'error': 'Password validation failed', 'details': password_errors}), 400
        
        # Check if user already exists
        if User.query.filter_by(email=data['email']).first():
            return jsonify({'error': 'Email already registered'}), 409
        
        # Validate NHS number if provided
        if data.get('nhs_number') and not validate_nhs_number(data['nhs_number']):
            return jsonify({'error': 'Invalid NHS number format'}), 400
        
        # Create new user
        user = User(
            email=data['email'].lower().strip(),
            first_name=data['first_name'].strip(),
            last_name=data['last_name'].strip(),
            phone=data.get('phone', '').strip(),
            role=UserRole.PATIENT,
            nhs_number=data.get('nhs_number', '').strip() or None,
            gp_practice_code=data.get('gp_practice_code', '').strip() or None
        )
        user.set_password(data['password'])
        
        db.session.add(user)
        db.session.flush()  # Get user ID
        
        # Create patient profile
        profile = PatientProfile(
            user_id=user.id,
            date_of_birth=datetime.strptime(data['date_of_birth'], '%Y-%m-%d').date() if data.get('date_of_birth') else None,
            gender=data.get('gender', '').strip() or None,
            emergency_contact_name=data.get('emergency_contact_name', '').strip() or None,
            emergency_contact_phone=data.get('emergency_contact_phone', '').strip() or None
        )
        
        db.session.add(profile)
        db.session.commit()
        
        # Create FHIR patient record for NHS interoperability
        try:
            fhir_patient_id = create_fhir_patient(user, profile)
            current_app.logger.info(f'FHIR patient created with ID: {fhir_patient_id}')
        except Exception as e:
            current_app.logger.error(f'Failed to create FHIR patient: {str(e)}')
        
        # Generate tokens
        access_token = create_access_token(identity=user.id)
        refresh_token = create_refresh_token(identity=user.id)
        
        return jsonify({
            'message': 'Patient registered successfully',
            'user': user.to_dict(),
            'access_token': access_token,
            'refresh_token': refresh_token
        }), 201
        
    except Exception as e:
        db.session.rollback()
        current_app.logger.error(f'Registration error: {str(e)}')
        return jsonify({'error': 'Registration failed'}), 500

@patient_bp.route('/login', methods=['POST'])
def login():
    """Patient login with secure authentication"""
    try:
        data = request.get_json()
        
        if not data.get('email') or not data.get('password'):
            return jsonify({'error': 'Email and password are required'}), 400
        
        user = User.query.filter_by(email=data['email'].lower().strip()).first()
        
        if not user or not user.check_password(data['password']):
            return jsonify({'error': 'Invalid credentials'}), 401
        
        if not user.is_active:
            return jsonify({'error': 'Account is deactivated'}), 403
        
        # Update last login
        user.last_login = datetime.utcnow()
        db.session.commit()
        
        # Generate tokens
        access_token = create_access_token(identity=user.id)
        refresh_token = create_refresh_token(identity=user.id)
        
        return jsonify({
            'message': 'Login successful',
            'user': user.to_dict(),
            'access_token': access_token,
            'refresh_token': refresh_token
        }), 200
        
    except Exception as e:
        current_app.logger.error(f'Login error: {str(e)}')
        return jsonify({'error': 'Login failed'}), 500

@patient_bp.route('/profile', methods=['GET'])
@jwt_required()
def get_profile():
    """Get patient profile"""
    try:
        user_id = get_jwt_identity()
        user = User.query.get(user_id)
        
        if not user:
            return jsonify({'error': 'User not found'}), 404
        
        profile_data = user.to_dict()
        
        if user.patient_profile:
            profile_data.update({
                'date_of_birth': user.patient_profile.date_of_birth.isoformat() if user.patient_profile.date_of_birth else None,
                'gender': user.patient_profile.gender,
                'height': user.patient_profile.height,
                'weight': user.patient_profile.weight,
                'blood_type': user.patient_profile.blood_type,
                'emergency_contact_name': user.patient_profile.emergency_contact_name,
                'emergency_contact_phone': user.patient_profile.emergency_contact_phone,
                'medical_conditions': user.patient_profile.medical_conditions,
                'medications': user.patient_profile.medications,
                'allergies': user.patient_profile.allergies,
                'care_plan': user.patient_profile.care_plan
            })
        
        return jsonify({'profile': profile_data}), 200
        
    except Exception as e:
        current_app.logger.error(f'Get profile error: {str(e)}')
        return jsonify({'error': 'Failed to retrieve profile'}), 500

@patient_bp.route('/profile', methods=['PUT'])
@jwt_required()
def update_profile():
    """Update patient profile"""
    try:
        user_id = get_jwt_identity()
        user = User.query.get(user_id)
        
        if not user:
            return jsonify({'error': 'User not found'}), 404
        
        data = request.get_json()
        
        # Update user fields
        if 'first_name' in data:
            user.first_name = data['first_name'].strip()
        if 'last_name' in data:
            user.last_name = data['last_name'].strip()
        if 'phone' in data:
            user.phone = data['phone'].strip()
        if 'email' in data and data['email'] != user.email:
            if validate_email(data['email']):
                # Check if email is already taken
                existing_user = User.query.filter_by(email=data['email'].lower()).first()
                if existing_user and existing_user.id != user.id:
                    return jsonify({'error': 'Email already in use'}), 409
                user.email = data['email'].lower().strip()
            else:
                return jsonify({'error': 'Invalid email format'}), 400
        
        user.updated_at = datetime.utcnow()
        
        # Update patient profile
        if not user.patient_profile:
            user.patient_profile = PatientProfile(user_id=user.id)
        
        profile = user.patient_profile
        
        if 'date_of_birth' in data and data['date_of_birth']:
            profile.date_of_birth = datetime.strptime(data['date_of_birth'], '%Y-%m-%d').date()
        if 'gender' in data:
            profile.gender = data['gender']
        if 'height' in data:
            profile.height = float(data['height']) if data['height'] else None
        if 'weight' in data:
            profile.weight = float(data['weight']) if data['weight'] else None
        if 'blood_type' in data:
            profile.blood_type = data['blood_type']
        if 'emergency_contact_name' in data:
            profile.emergency_contact_name = data['emergency_contact_name']
        if 'emergency_contact_phone' in data:
            profile.emergency_contact_phone = data['emergency_contact_phone']
        if 'medical_conditions' in data:
            profile.medical_conditions = data['medical_conditions']
        if 'medications' in data:
            profile.medications = data['medications']
        if 'allergies' in data:
            profile.allergies = data['allergies']
        if 'care_plan' in data:
            profile.care_plan = data['care_plan']
        
        profile.updated_at = datetime.utcnow()
        
        db.session.commit()
        
        # Update FHIR patient record
        try:
            update_fhir_patient(user, profile)
            current_app.logger.info(f'FHIR patient updated for user ID: {user.id}')
        except Exception as e:
            current_app.logger.error(f'Failed to update FHIR patient: {str(e)}')
        
        return jsonify({
            'message': 'Profile updated successfully',
            'profile': user.to_dict()
        }), 200
        
    except Exception as e:
        db.session.rollback()
        current_app.logger.error(f'Update profile error: {str(e)}')
        return jsonify({'error': 'Failed to update profile'}), 500

@patient_bp.route('/change-password', methods=['POST'])
@jwt_required()
def change_password():
    """Change patient password"""
    try:
        user_id = get_jwt_identity()
        user = User.query.get(user_id)
        
        if not user:
            return jsonify({'error': 'User not found'}), 404
        
        data = request.get_json()
        
        if not data.get('current_password') or not data.get('new_password'):
            return jsonify({'error': 'Current password and new password are required'}), 400
        
        if not user.check_password(data['current_password']):
            return jsonify({'error': 'Current password is incorrect'}), 400
        
        # Validate new password
        password_errors = validate_password(data['new_password'])
        if password_errors:
            return jsonify({'error': 'New password validation failed', 'details': password_errors}), 400
        
        user.set_password(data['new_password'])
        user.updated_at = datetime.utcnow()
        db.session.commit()
        
        return jsonify({'message': 'Password changed successfully'}), 200
        
    except Exception as e:
        db.session.rollback()
        current_app.logger.error(f'Change password error: {str(e)}')
        return jsonify({'error': 'Failed to change password'}), 500

@patient_bp.route('/refresh', methods=['POST'])
@jwt_required(refresh=True)
def refresh():
    """Refresh access token"""
    try:
        user_id = get_jwt_identity()
        access_token = create_access_token(identity=user_id)
        return jsonify({'access_token': access_token}), 200
    except Exception as e:
        current_app.logger.error(f'Token refresh error: {str(e)}')
        return jsonify({'error': 'Token refresh failed'}), 500
