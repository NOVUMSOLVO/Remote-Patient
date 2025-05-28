"""
Role-Based Access Control (RBAC) Module for Remote Patient Monitoring
Manages user roles, permissions, and access control
"""

from flask import Blueprint, request, jsonify, current_app
from flask_jwt_extended import jwt_required, get_jwt_identity, get_jwt
from sqlalchemy.exc import IntegrityError
from app.models import (
    db, User, PatientProfile, HealthcareProvider, 
    UserRole, ProviderType
)
from app.utils.validation import validate_email
from functools import wraps
import logging

rbac_bp = Blueprint('rbac', __name__, url_prefix='/api/rbac')
logger = logging.getLogger(__name__)

# Permission decorators
def admin_required(f):
    """Decorator to require admin role"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        current_user_id = get_jwt_identity()
        user = User.query.get(current_user_id)
        if not user or user.role != UserRole.ADMIN:
            return jsonify({'error': 'Admin access required'}), 403
        return f(*args, **kwargs)
    return decorated_function

def healthcare_provider_required(f):
    """Decorator to require healthcare provider role"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        current_user_id = get_jwt_identity()
        user = User.query.get(current_user_id)
        if not user or user.role not in [UserRole.HEALTHCARE_PROVIDER, UserRole.ADMIN]:
            return jsonify({'error': 'Healthcare provider access required'}), 403
        return f(*args, **kwargs)
    return decorated_function

def patient_or_provider_required(f):
    """Decorator to require patient or healthcare provider role"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        current_user_id = get_jwt_identity()
        user = User.query.get(current_user_id)
        if not user or user.role == UserRole.SYSTEM:
            return jsonify({'error': 'Patient or healthcare provider access required'}), 403
        return f(*args, **kwargs)
    return decorated_function

def patient_data_access_required(patient_id):
    """Check if current user has access to specific patient data"""
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            current_user_id = get_jwt_identity()
            user = User.query.get(current_user_id)
            
            if not user:
                return jsonify({'error': 'User not found'}), 404
            
            # Admin has access to all data
            if user.role == UserRole.ADMIN:
                return f(*args, **kwargs)
            
            # Patient can only access their own data
            if user.role == UserRole.PATIENT:
                patient_profile = PatientProfile.query.filter_by(user_id=current_user_id).first()
                if not patient_profile or str(patient_profile.id) != str(patient_id):
                    return jsonify({'error': 'Access denied to patient data'}), 403
                return f(*args, **kwargs)
            
            # Healthcare provider can access assigned patients
            if user.role == UserRole.HEALTHCARE_PROVIDER:
                provider = HealthcareProvider.query.filter_by(user_id=current_user_id).first()
                if not provider:
                    return jsonify({'error': 'Healthcare provider profile not found'}), 404
                
                # Check if provider is assigned to this patient
                patient = PatientProfile.query.get(patient_id)
                if not patient or patient.primary_provider_id != provider.id:
                    return jsonify({'error': 'Access denied to patient data'}), 403
                return f(*args, **kwargs)
            
            return jsonify({'error': 'Access denied'}), 403
        return decorated_function
    return decorator

@rbac_bp.route('/users', methods=['GET'])
@jwt_required()
@admin_required
def get_all_users():
    """Get all users (admin only)"""
    try:
        page = request.args.get('page', 1, type=int)
        per_page = request.args.get('per_page', 20, type=int)
        role_filter = request.args.get('role')
        search = request.args.get('search', '')
        
        query = User.query
        
        # Apply role filter
        if role_filter:
            try:
                role_enum = UserRole(role_filter)
                query = query.filter(User.role == role_enum)
            except ValueError:
                return jsonify({'error': 'Invalid role filter'}), 400
        
        # Apply search filter
        if search:
            search_filter = f"%{search}%"
            query = query.filter(
                db.or_(
                    User.email.ilike(search_filter),
                    User.first_name.ilike(search_filter),
                    User.last_name.ilike(search_filter)
                )
            )
        
        # Apply pagination
        users_pagination = query.paginate(
            page=page, per_page=per_page, error_out=False
        )
        
        users_data = []
        for user in users_pagination.items:
            user_data = {
                'id': user.id,
                'email': user.email,
                'first_name': user.first_name,
                'last_name': user.last_name,
                'role': user.role.value,
                'is_active': user.is_active,
                'email_verified': user.email_verified,
                'created_at': user.created_at.isoformat(),
                'last_login': user.last_login.isoformat() if user.last_login else None
            }
            
            # Add role-specific information
            if user.role == UserRole.PATIENT:
                patient = PatientProfile.query.filter_by(user_id=user.id).first()
                if patient:
                    user_data['patient_profile'] = {
                        'nhs_number': patient.nhs_number,
                        'date_of_birth': patient.date_of_birth.isoformat() if patient.date_of_birth else None,
                        'phone_number': patient.phone_number,
                        'emergency_contact_name': patient.emergency_contact_name,
                        'emergency_contact_phone': patient.emergency_contact_phone
                    }
            elif user.role == UserRole.HEALTHCARE_PROVIDER:
                provider = HealthcareProvider.query.filter_by(user_id=user.id).first()
                if provider:
                    user_data['provider_profile'] = {
                        'license_number': provider.license_number,
                        'provider_type': provider.provider_type.value if provider.provider_type else None,
                        'specialization': provider.specialization,
                        'organization': provider.organization,
                        'verified': provider.verified
                    }
            
            users_data.append(user_data)
        
        return jsonify({
            'users': users_data,
            'pagination': {
                'page': page,
                'per_page': per_page,
                'total': users_pagination.total,
                'pages': users_pagination.pages,
                'has_next': users_pagination.has_next,
                'has_prev': users_pagination.has_prev
            }
        }), 200
        
    except Exception as e:
        logger.error(f"Error fetching users: {str(e)}")
        return jsonify({'error': 'Failed to fetch users'}), 500

@rbac_bp.route('/users/<int:user_id>', methods=['GET'])
@jwt_required()
@admin_required
def get_user_details(user_id):
    """Get detailed user information (admin only)"""
    try:
        user = User.query.get(user_id)
        if not user:
            return jsonify({'error': 'User not found'}), 404
        
        user_data = {
            'id': user.id,
            'email': user.email,
            'first_name': user.first_name,
            'last_name': user.last_name,
            'role': user.role.value,
            'is_active': user.is_active,
            'email_verified': user.email_verified,
            'created_at': user.created_at.isoformat(),
            'last_login': user.last_login.isoformat() if user.last_login else None
        }
        
        # Add role-specific detailed information
        if user.role == UserRole.PATIENT:
            patient = PatientProfile.query.filter_by(user_id=user.id).first()
            if patient:
                user_data['patient_profile'] = {
                    'id': patient.id,
                    'nhs_number': patient.nhs_number,
                    'date_of_birth': patient.date_of_birth.isoformat() if patient.date_of_birth else None,
                    'gender': patient.gender,
                    'phone_number': patient.phone_number,
                    'address': patient.address,
                    'emergency_contact_name': patient.emergency_contact_name,
                    'emergency_contact_phone': patient.emergency_contact_phone,
                    'medical_conditions': patient.medical_conditions,
                    'medications': patient.medications,
                    'allergies': patient.allergies,
                    'insurance_info': patient.insurance_info,
                    'primary_provider_id': patient.primary_provider_id,
                    'created_at': patient.created_at.isoformat()
                }
        elif user.role == UserRole.HEALTHCARE_PROVIDER:
            provider = HealthcareProvider.query.filter_by(user_id=user.id).first()
            if provider:
                user_data['provider_profile'] = {
                    'id': provider.id,
                    'license_number': provider.license_number,
                    'provider_type': provider.provider_type.value if provider.provider_type else None,
                    'specialization': provider.specialization,
                    'organization': provider.organization,
                    'phone_number': provider.phone_number,
                    'address': provider.address,
                    'verified': provider.verified,
                    'created_at': provider.created_at.isoformat()
                }
        
        return jsonify(user_data), 200
        
    except Exception as e:
        logger.error(f"Error fetching user details: {str(e)}")
        return jsonify({'error': 'Failed to fetch user details'}), 500

@rbac_bp.route('/users/<int:user_id>/role', methods=['PUT'])
@jwt_required()
@admin_required
def update_user_role(user_id):
    """Update user role (admin only)"""
    try:
        data = request.get_json()
        new_role = data.get('role')
        
        if not new_role:
            return jsonify({'error': 'Role is required'}), 400
        
        try:
            role_enum = UserRole(new_role)
        except ValueError:
            return jsonify({'error': 'Invalid role'}), 400
        
        user = User.query.get(user_id)
        if not user:
            return jsonify({'error': 'User not found'}), 404
        
        # Prevent admin from changing their own role
        current_user_id = get_jwt_identity()
        if user_id == current_user_id:
            return jsonify({'error': 'Cannot change your own role'}), 400
        
        old_role = user.role
        user.role = role_enum
        
        try:
            db.session.commit()
            logger.info(f"User role updated: {user.email} from {old_role.value} to {role_enum.value}")
            
            return jsonify({
                'message': 'User role updated successfully',
                'user_id': user_id,
                'old_role': old_role.value,
                'new_role': role_enum.value
            }), 200
            
        except IntegrityError:
            db.session.rollback()
            return jsonify({'error': 'Database error during role update'}), 500
        
    except Exception as e:
        logger.error(f"Error updating user role: {str(e)}")
        return jsonify({'error': 'Failed to update user role'}), 500

@rbac_bp.route('/users/<int:user_id>/status', methods=['PUT'])
@jwt_required()
@admin_required
def update_user_status(user_id):
    """Update user active status (admin only)"""
    try:
        data = request.get_json()
        is_active = data.get('is_active')
        
        if is_active is None:
            return jsonify({'error': 'is_active status is required'}), 400
        
        user = User.query.get(user_id)
        if not user:
            return jsonify({'error': 'User not found'}), 404
        
        # Prevent admin from deactivating themselves
        current_user_id = get_jwt_identity()
        if user_id == current_user_id and not is_active:
            return jsonify({'error': 'Cannot deactivate your own account'}), 400
        
        old_status = user.is_active
        user.is_active = is_active
        
        try:
            db.session.commit()
            logger.info(f"User status updated: {user.email} from {old_status} to {is_active}")
            
            return jsonify({
                'message': 'User status updated successfully',
                'user_id': user_id,
                'old_status': old_status,
                'new_status': is_active
            }), 200
            
        except IntegrityError:
            db.session.rollback()
            return jsonify({'error': 'Database error during status update'}), 500
        
    except Exception as e:
        logger.error(f"Error updating user status: {str(e)}")
        return jsonify({'error': 'Failed to update user status'}), 500

@rbac_bp.route('/permissions/check', methods=['POST'])
@jwt_required()
def check_permissions():
    """Check user permissions for specific actions"""
    try:
        data = request.get_json()
        action = data.get('action')
        resource = data.get('resource')
        resource_id = data.get('resource_id')
        
        current_user_id = get_jwt_identity()
        user = User.query.get(current_user_id)
        
        if not user:
            return jsonify({'error': 'User not found'}), 404
        
        permissions = {
            'can_access': False,
            'can_read': False,
            'can_write': False,
            'can_delete': False
        }
        
        # Admin has all permissions
        if user.role == UserRole.ADMIN:
            permissions = {
                'can_access': True,
                'can_read': True,
                'can_write': True,
                'can_delete': True
            }
        
        # Patient permissions
        elif user.role == UserRole.PATIENT:
            if resource == 'patient_profile':
                patient = PatientProfile.query.filter_by(user_id=current_user_id).first()
                if patient and (not resource_id or str(patient.id) == str(resource_id)):
                    permissions['can_access'] = True
                    permissions['can_read'] = True
                    permissions['can_write'] = True  # Can update own profile
            
            elif resource == 'health_records':
                patient = PatientProfile.query.filter_by(user_id=current_user_id).first()
                if patient:
                    permissions['can_access'] = True
                    permissions['can_read'] = True
            
            elif resource == 'devices':
                patient = PatientProfile.query.filter_by(user_id=current_user_id).first()
                if patient:
                    permissions['can_access'] = True
                    permissions['can_read'] = True
                    permissions['can_write'] = True  # Can manage own devices
        
        # Healthcare provider permissions
        elif user.role == UserRole.HEALTHCARE_PROVIDER:
            provider = HealthcareProvider.query.filter_by(user_id=current_user_id).first()
            if provider and provider.verified:
                if resource == 'patient_profiles':
                    permissions['can_access'] = True
                    permissions['can_read'] = True
                    permissions['can_write'] = True  # Can update assigned patients
                
                elif resource == 'health_records':
                    permissions['can_access'] = True
                    permissions['can_read'] = True
                    permissions['can_write'] = True  # Can create/update records
                
                elif resource == 'alerts':
                    permissions['can_access'] = True
                    permissions['can_read'] = True
                    permissions['can_write'] = True  # Can manage alerts
        
        return jsonify({
            'user_id': current_user_id,
            'role': user.role.value,
            'resource': resource,
            'resource_id': resource_id,
            'action': action,
            'permissions': permissions
        }), 200
        
    except Exception as e:
        logger.error(f"Error checking permissions: {str(e)}")
        return jsonify({'error': 'Failed to check permissions'}), 500

@rbac_bp.route('/roles', methods=['GET'])
@jwt_required()
@admin_required
def get_available_roles():
    """Get all available user roles (admin only)"""
    try:
        roles = [
            {
                'value': role.value,
                'name': role.name,
                'description': {
                    UserRole.ADMIN: 'Full system access and user management',
                    UserRole.HEALTHCARE_PROVIDER: 'Access to assigned patients and clinical features',
                    UserRole.PATIENT: 'Access to personal health data and monitoring',
                    UserRole.SYSTEM: 'System-level access for automated processes'
                }.get(role, 'No description available')
            }
            for role in UserRole
        ]
        
        return jsonify({'roles': roles}), 200
        
    except Exception as e:
        logger.error(f"Error fetching roles: {str(e)}")
        return jsonify({'error': 'Failed to fetch roles'}), 500

@rbac_bp.route('/audit-log', methods=['GET'])
@jwt_required()
@admin_required
def get_audit_log():
    """Get user activity audit log (admin only)"""
    try:
        page = request.args.get('page', 1, type=int)
        per_page = request.args.get('per_page', 50, type=int)
        user_id_filter = request.args.get('user_id', type=int)
        action_filter = request.args.get('action')
        
        # This would typically come from an audit log table
        # For now, return a placeholder response
        # TODO: Implement proper audit logging
        
        return jsonify({
            'message': 'Audit logging not yet implemented',
            'audit_entries': [],
            'pagination': {
                'page': page,
                'per_page': per_page,
                'total': 0,
                'pages': 0
            }
        }), 200
        
    except Exception as e:
        logger.error(f"Error fetching audit log: {str(e)}")
        return jsonify({'error': 'Failed to fetch audit log'}), 500
