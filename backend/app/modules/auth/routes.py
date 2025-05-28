"""
Enhanced Authentication Module with Multi-Factor Authentication
Implements NHS Digital security standards and comprehensive authentication
"""

from flask import Blueprint, request, jsonify, current_app
from flask_jwt_extended import (
    jwt_required, get_jwt_identity, create_access_token, 
    create_refresh_token, get_jwt
)
from datetime import datetime, timedelta
from app.models import db, User, UserRole
from app.utils.security import (
    security_manager, mfa_manager, session_manager, 
    rate_limiter, audit_logger
)
from app.utils.nhs_cis2 import (
    create_nhs_cis2_client, validate_nhs_authentication,
    NHS_Data_Standards, NHS_Smartcard_Validator
)
from app.utils.validation import validate_email, validate_password
import logging
import base64

auth_bp = Blueprint('auth', __name__, url_prefix='/api/auth')
logger = logging.getLogger(__name__)

@auth_bp.before_request
def rate_limit_check():
    """Apply rate limiting to authentication endpoints"""
    if not current_app.config.get('RATE_LIMIT_ENABLED', True):
        return
    
    ip_address = request.remote_addr
    endpoint = request.endpoint
    
    # Different rate limits for different endpoints
    if endpoint == 'auth.login':
        limit, window = 5, 300  # 5 attempts per 5 minutes
    elif endpoint == 'auth.register':
        limit, window = 3, 3600  # 3 attempts per hour
    else:
        limit, window = 100, 3600  # 100 requests per hour for other endpoints
    
    is_allowed, requests_made, time_until_reset = rate_limiter.is_allowed(
        f"{ip_address}:{endpoint}", limit, window
    )
    
    if not is_allowed:
        audit_logger.log_security_event(
            'rate_limit_exceeded', 
            None, 
            f"Rate limit exceeded for {endpoint} from {ip_address}",
            'warning'
        )
        return jsonify({
            'error': 'Too many requests',
            'retry_after': int(time_until_reset)
        }), 429

@auth_bp.route('/login', methods=['POST'])
def login():
    """Enhanced login with security features"""
    try:
        data = request.get_json()
        ip_address = request.remote_addr
        user_agent = request.headers.get('User-Agent', '')
        
        # Validate input
        if not data.get('email') or not data.get('password'):
            audit_logger.log_authentication_attempt(
                data.get('email', 'unknown'), ip_address, False, 'Missing credentials'
            )
            return jsonify({'error': 'Email and password are required'}), 400
        
        email = data['email'].lower().strip()
        password = data['password']
        
        # Check for user
        user = User.query.filter_by(email=email).first()
        
        if not user or not user.check_password(password):
            audit_logger.log_authentication_attempt(
                email, ip_address, False, 'Invalid credentials'
            )
            return jsonify({'error': 'Invalid credentials'}), 401
        
        if not user.is_active:
            audit_logger.log_authentication_attempt(
                email, ip_address, False, 'Account deactivated'
            )
            return jsonify({'error': 'Account is deactivated'}), 403
        
        # Check if MFA is required
        if user.mfa_enabled:
            if not data.get('mfa_token'):
                return jsonify({
                    'error': 'MFA token required',
                    'mfa_required': True
                }), 200
            
            # Verify MFA token
            if not mfa_manager.verify_totp(user.mfa_secret, data['mfa_token']):
                audit_logger.log_authentication_attempt(
                    email, ip_address, False, 'Invalid MFA token'
                )
                return jsonify({'error': 'Invalid MFA token'}), 401
        
        # Update user login information
        user.last_login = datetime.utcnow()
        user.last_login_ip = ip_address
        db.session.commit()
        
        # Create session
        session_id = session_manager.create_session(user.id, ip_address, user_agent)
        
        # Generate tokens
        access_token = create_access_token(
            identity=user.id,
            additional_claims={'session_id': session_id}
        )
        refresh_token = create_refresh_token(identity=user.id)
        
        # Log successful authentication
        audit_logger.log_authentication_attempt(email, ip_address, True)
        
        return jsonify({
            'message': 'Login successful',
            'user': user.to_dict(),
            'access_token': access_token,
            'refresh_token': refresh_token,
            'session_expires_at': (datetime.utcnow() + timedelta(
                minutes=current_app.config.get('SESSION_TIMEOUT_MINUTES', 120)
            )).isoformat()
        }), 200
        
    except Exception as e:
        logger.error(f'Login error: {str(e)}')
        return jsonify({'error': 'Authentication failed'}), 500

@auth_bp.route('/logout', methods=['POST'])
@jwt_required()
def logout():
    """Enhanced logout with session cleanup"""
    try:
        user_id = get_jwt_identity()
        claims = get_jwt()
        session_id = claims.get('session_id')
        
        # Destroy session
        if session_id:
            session_manager.destroy_session(session_id)
        
        # Log logout
        audit_logger.log_security_event(
            'logout', user_id, 'User logged out', 'info'
        )
        
        return jsonify({'message': 'Logout successful'}), 200
        
    except Exception as e:
        logger.error(f'Logout error: {str(e)}')
        return jsonify({'error': 'Logout failed'}), 500

@auth_bp.route('/setup-mfa', methods=['POST'])
@jwt_required()
def setup_mfa():
    """Set up Multi-Factor Authentication"""
    try:
        user_id = get_jwt_identity()
        user = User.query.get(user_id)
        
        if not user:
            return jsonify({'error': 'User not found'}), 404
        
        # Generate MFA secret
        secret = mfa_manager.generate_secret()
        
        # Generate QR code
        qr_code_buffer = mfa_manager.generate_qr_code(user.email, secret)
        qr_code_data = base64.b64encode(qr_code_buffer.getvalue()).decode()
        
        # Generate backup codes
        backup_codes = mfa_manager.generate_backup_codes()
        
        # Store secret temporarily (not activated until verified)
        user.mfa_secret_temp = secret
        user.mfa_backup_codes = ','.join(backup_codes)
        db.session.commit()
        
        return jsonify({
            'secret': secret,
            'qr_code': f"data:image/png;base64,{qr_code_data}",
            'backup_codes': backup_codes
        }), 200
        
    except Exception as e:
        logger.error(f'MFA setup error: {str(e)}')
        return jsonify({'error': 'MFA setup failed'}), 500

@auth_bp.route('/verify-mfa', methods=['POST'])
@jwt_required()
def verify_mfa():
    """Verify and activate MFA"""
    try:
        user_id = get_jwt_identity()
        user = User.query.get(user_id)
        data = request.get_json()
        
        if not user or not data.get('token'):
            return jsonify({'error': 'Invalid request'}), 400
        
        if not user.mfa_secret_temp:
            return jsonify({'error': 'No MFA setup in progress'}), 400
        
        # Verify token
        if not mfa_manager.verify_totp(user.mfa_secret_temp, data['token']):
            return jsonify({'error': 'Invalid MFA token'}), 401
        
        # Activate MFA
        user.mfa_secret = user.mfa_secret_temp
        user.mfa_secret_temp = None
        user.mfa_enabled = True
        user.mfa_enabled_at = datetime.utcnow()
        db.session.commit()
        
        # Log MFA activation
        audit_logger.log_security_event(
            'mfa_enabled', user_id, 'Multi-factor authentication enabled', 'info'
        )
        
        return jsonify({'message': 'MFA activated successfully'}), 200
        
    except Exception as e:
        logger.error(f'MFA verification error: {str(e)}')
        return jsonify({'error': 'MFA verification failed'}), 500

@auth_bp.route('/disable-mfa', methods=['POST'])
@jwt_required()
def disable_mfa():
    """Disable Multi-Factor Authentication"""
    try:
        user_id = get_jwt_identity()
        user = User.query.get(user_id)
        data = request.get_json()
        
        if not user:
            return jsonify({'error': 'User not found'}), 404
        
        if not user.mfa_enabled:
            return jsonify({'error': 'MFA is not enabled'}), 400
        
        # Verify current password
        if not data.get('password') or not user.check_password(data['password']):
            return jsonify({'error': 'Invalid password'}), 401
        
        # Disable MFA
        user.mfa_enabled = False
        user.mfa_secret = None
        user.mfa_backup_codes = None
        user.mfa_disabled_at = datetime.utcnow()
        db.session.commit()
        
        # Log MFA deactivation
        audit_logger.log_security_event(
            'mfa_disabled', user_id, 'Multi-factor authentication disabled', 'warning'
        )
        
        return jsonify({'message': 'MFA disabled successfully'}), 200
        
    except Exception as e:
        logger.error(f'MFA disable error: {str(e)}')
        return jsonify({'error': 'MFA disable failed'}), 500

@auth_bp.route('/change-password', methods=['POST'])
@jwt_required()
def change_password():
    """Enhanced password change with security features"""
    try:
        user_id = get_jwt_identity()
        user = User.query.get(user_id)
        data = request.get_json()
        
        if not user:
            return jsonify({'error': 'User not found'}), 404
        
        current_password = data.get('current_password')
        new_password = data.get('new_password')
        
        if not current_password or not new_password:
            return jsonify({'error': 'Current and new passwords are required'}), 400
        
        # Verify current password
        if not user.check_password(current_password):
            audit_logger.log_security_event(
                'password_change_failed', user_id, 'Invalid current password', 'warning'
            )
            return jsonify({'error': 'Current password is incorrect'}), 401
        
        # Validate new password
        password_errors = validate_password(new_password)
        if password_errors:
            return jsonify({
                'error': 'Password validation failed',
                'details': password_errors
            }), 400
        
        # Check password history (if implemented)
        if hasattr(user, 'password_history') and user.password_history:
            # Simple check - in production, implement proper password history
            if user.check_password(new_password):
                return jsonify({
                    'error': 'New password cannot be the same as current password'
                }), 400
        
        # Update password
        user.set_password(new_password)
        user.password_changed_at = datetime.utcnow()
        user.updated_at = datetime.utcnow()
        db.session.commit()
        
        # Log password change
        audit_logger.log_security_event(
            'password_changed', user_id, 'Password changed successfully', 'info'
        )
        
        return jsonify({'message': 'Password changed successfully'}), 200
        
    except Exception as e:
        logger.error(f'Password change error: {str(e)}')
        return jsonify({'error': 'Password change failed'}), 500

@auth_bp.route('/verify-session', methods=['GET'])
@jwt_required()
def verify_session():
    """Verify session and token validity"""
    try:
        user_id = get_jwt_identity()
        claims = get_jwt()
        session_id = claims.get('session_id')
        
        user = User.query.get(user_id)
        if not user or not user.is_active:
            return jsonify({'error': 'Invalid session'}), 401
        
        # Verify session if session_id exists
        if session_id:
            session_data = session_manager.validate_session(
                session_id, 
                request.remote_addr, 
                request.headers.get('User-Agent', '')
            )
            
            if not session_data:
                return jsonify({'error': 'Session expired or invalid'}), 401
        
        return jsonify({
            'user': user.to_dict(),
            'session_valid': True
        }), 200
        
    except Exception as e:
        logger.error(f'Session verification error: {str(e)}')
        return jsonify({'error': 'Session verification failed'}), 500

@auth_bp.route('/refresh', methods=['POST'])
@jwt_required(refresh=True)
def refresh_token():
    """Refresh access token"""
    try:
        user_id = get_jwt_identity()
        user = User.query.get(user_id)
        
        if not user or not user.is_active:
            return jsonify({'error': 'Invalid user'}), 401
        
        # Create new session
        session_id = session_manager.create_session(
            user.id, 
            request.remote_addr, 
            request.headers.get('User-Agent', '')
        )
        
        # Generate new access token
        access_token = create_access_token(
            identity=user_id,
            additional_claims={'session_id': session_id}
        )
        
        return jsonify({
            'access_token': access_token,
            'session_expires_at': (datetime.utcnow() + timedelta(
                minutes=current_app.config.get('SESSION_TIMEOUT_MINUTES', 120)
            )).isoformat()
        }), 200
        
    except Exception as e:
        logger.error(f'Token refresh error: {str(e)}')
        return jsonify({'error': 'Token refresh failed'}), 500

@auth_bp.route('/security-status', methods=['GET'])
@jwt_required()
def get_security_status():
    """Get user's security status and recommendations"""
    try:
        user_id = get_jwt_identity()
        user = User.query.get(user_id)
        
        if not user:
            return jsonify({'error': 'User not found'}), 404
        
        # Calculate security score and recommendations
        security_score = 0
        recommendations = []
        
        # Check MFA
        if user.mfa_enabled:
            security_score += 30
        else:
            recommendations.append("Enable Multi-Factor Authentication for enhanced security")
        
        # Check password age (if implemented)
        if hasattr(user, 'password_changed_at') and user.password_changed_at:
            days_since_change = (datetime.utcnow() - user.password_changed_at).days
            if days_since_change < 90:
                security_score += 20
            else:
                recommendations.append("Consider changing your password (last changed over 90 days ago)")
        
        # Check recent login activity
        if user.last_login and (datetime.utcnow() - user.last_login).days < 30:
            security_score += 10
        
        # Base security features
        security_score += 40  # For having account, basic encryption, etc.
        
        return jsonify({
            'security_score': min(security_score, 100),
            'mfa_enabled': user.mfa_enabled,
            'last_login': user.last_login.isoformat() if user.last_login else None,
            'last_login_ip': getattr(user, 'last_login_ip', None),
            'recommendations': recommendations
        }), 200
        
    except Exception as e:
        logger.error(f'Security status error: {str(e)}')
        return jsonify({'error': 'Failed to get security status'}), 500

@auth_bp.route('/nhs-login', methods=['POST'])
def nhs_login():
    """NHS Login with Smartcard and MFA support"""
    try:
        data = request.get_json()
        ip_address = request.remote_addr
        user_agent = request.headers.get('User-Agent', '')
        
        # Validate input
        if not data.get('smartcard_number') or not data.get('smartcard_password'):
            audit_logger.log_authentication_attempt(
                data.get('smartcard_number', 'unknown'), ip_address, False, 'Missing credentials'
            )
            return jsonify({'error': 'Smartcard number and password are required'}), 400
        
        smartcard_number = data['smartcard_number'].strip()
        smartcard_password = data['smartcard_password']
        
        # Validate NHS Smartcard
        nhs_client = create_nhs_cis2_client()
        smartcard_valid, user_info = nhs_client.validate_smartcard(
            smartcard_number, smartcard_password
        )
        
        if not smartcard_valid:
            audit_logger.log_authentication_attempt(
                smartcard_number, ip_address, False, 'Invalid Smartcard credentials'
            )
            return jsonify({'error': 'Invalid Smartcard credentials'}), 401
        
        # Check for user
        user = User.query.filter_by(smartcard_number=smartcard_number).first()
        
        if not user:
            # Register new user based on NHS data
            user_data = nhs_client.get_user_info(smartcard_number)
            user = User(
                email=user_data['email'],
                smartcard_number=smartcard_number,
                first_name=user_data['first_name'],
                last_name=user_data['last_name'],
                role=UserRole.query.filter_by(name='patient').first(),
                is_active=True
            )
            user.set_password(security_manager.generate_random_password())
            db.session.add(user)
            db.session.commit()
            
            audit_logger.log_authentication_attempt(
                smartcard_number, ip_address, True, 'New user registered'
            )
        else:
            # Update user login information
            user.last_login = datetime.utcnow()
            user.last_login_ip = ip_address
            db.session.commit()
        
        # Check if MFA is required
        if user.mfa_enabled:
            if not data.get('mfa_token'):
                return jsonify({
                    'error': 'MFA token required',
                    'mfa_required': True
                }), 200
            
            # Verify MFA token
            if not mfa_manager.verify_totp(user.mfa_secret, data['mfa_token']):
                audit_logger.log_authentication_attempt(
                    smartcard_number, ip_address, False, 'Invalid MFA token'
                )
                return jsonify({'error': 'Invalid MFA token'}), 401
        
        # Create session
        session_id = session_manager.create_session(user.id, ip_address, user_agent)
        
        # Generate tokens
        access_token = create_access_token(
            identity=user.id,
            additional_claims={'session_id': session_id}
        )
        refresh_token = create_refresh_token(identity=user.id)
        
        # Log successful authentication
        audit_logger.log_authentication_attempt(smartcard_number, ip_address, True)
        
        return jsonify({
            'message': 'Login successful',
            'user': user.to_dict(),
            'access_token': access_token,
            'refresh_token': refresh_token,
            'session_expires_at': (datetime.utcnow() + timedelta(
                minutes=current_app.config.get('SESSION_TIMEOUT_MINUTES', 120)
            )).isoformat()
        }), 200
        
    except Exception as e:
        logger.error(f'NHS Login error: {str(e)}')
        return jsonify({'error': 'NHS authentication failed'}), 500

@auth_bp.route('/nhs-verify', methods=['POST'])
@jwt_required()
def nhs_verify():
    """Verify NHS authentication status and refresh tokens"""
    try:
        user_id = get_jwt_identity()
        user = User.query.get(user_id)
        data = request.get_json()
        
        if not user:
            return jsonify({'error': 'User not found'}), 404
        
        # Validate NHS authentication
        nhs_client = create_nhs_cis2_client()
        valid, user_info = nhs_client.validate_authentication(user.smartcard_number)
        
        if not valid:
            return jsonify({'error': 'NHS authentication failed'}), 401
        
        # Refresh user information if needed
        if user_info.get('last_updated') > user.updated_at:
            user.email = user_info['email']
            user.first_name = user_info['first_name']
            user.last_name = user_info['last_name']
            user.updated_at = datetime.utcnow()
            db.session.commit()
        
        # Generate new session
        session_id = session_manager.create_session(
            user.id, 
            request.remote_addr, 
            request.headers.get('User-Agent', '')
        )
        
        # Generate new access token
        access_token = create_access_token(
            identity=user_id,
            additional_claims={'session_id': session_id}
        )
        
        return jsonify({
            'access_token': access_token,
            'session_expires_at': (datetime.utcnow() + timedelta(
                minutes=current_app.config.get('SESSION_TIMEOUT_MINUTES', 120)
            )).isoformat()
        }), 200
        
    except Exception as e:
        logger.error(f'NHS Verify error: {str(e)}')
        return jsonify({'error': 'NHS verification failed'}), 500

# NHS CIS2 OAuth Authentication Endpoints

@auth_bp.route('/nhs-cis2/authorize', methods=['GET'])
def nhs_cis2_authorize():
    """Initiate NHS CIS2 OAuth authentication"""
    try:
        nhs_client = create_nhs_cis2_client()
        auth_url, state = nhs_client.generate_authorization_url()
        
        audit_logger.log_security_event(
            event_type='nhs_auth_initiated',
            user_id=None,
            ip_address=request.remote_addr,
            details='NHS CIS2 authentication initiated'
        )
        
        return jsonify({
            'auth_url': auth_url,
            'state': state
        }), 200
        
    except Exception as e:
        logger.error(f'NHS CIS2 authorization error: {str(e)}')
        return jsonify({'error': 'Failed to initiate NHS authentication'}), 500

@auth_bp.route('/nhs-cis2/callback', methods=['POST'])
def nhs_cis2_callback():
    """Handle NHS CIS2 OAuth callback"""
    try:
        data = request.get_json()
        authorization_code = data.get('code')
        state = data.get('state')
        
        if not authorization_code or not state:
            return jsonify({'error': 'Missing authorization code or state'}), 400
        
        nhs_client = create_nhs_cis2_client()
        
        # Exchange code for tokens
        token_data = nhs_client.exchange_code_for_token(authorization_code, state)
        
        # Get user information
        user_info = nhs_client.get_user_info(token_data['access_token'])
        
        # Validate NHS authentication
        nhs_payload = validate_nhs_authentication(token_data)
        
        # Extract NHS number and organisation details
        nhs_number = user_info.get('nhs_number')
        organisation_code = user_info.get('organisation_code')
        
        if nhs_number and not NHS_Data_Standards.validate_nhs_number(nhs_number):
            return jsonify({'error': 'Invalid NHS number'}), 400
        
        # Check for existing user
        user = User.query.filter_by(nhs_number=nhs_number).first()
        
        if not user:
            # Create new user from NHS data
            role_profile = nhs_payload.get('smartcard', {}).get('role_profile')
            user_role = NHS_Smartcard_Validator.extract_user_role(role_profile)
            
            user = User(
                email=user_info.get('email'),
                nhs_number=nhs_number,
                first_name=user_info.get('given_name'),
                last_name=user_info.get('family_name'),
                role=user_role,
                organisation_code=organisation_code,
                smartcard_uid=nhs_payload.get('smartcard', {}).get('uid'),
                is_active=True,
                created_at=datetime.utcnow()
            )
            
            # Set secure random password (not used for NHS login)
            import secrets
            random_password = secrets.token_urlsafe(32)
            user.password_hash = security_manager.hash_password(random_password)
            
            db.session.add(user)
            db.session.flush()
            
            audit_logger.log_security_event(
                event_type='nhs_user_created',
                user_id=user.id,
                ip_address=request.remote_addr,
                details=f'New NHS user created with organisation: {organisation_code}'
            )
        else:
            # Update existing user information
            user.last_login = datetime.utcnow()
            user.last_login_ip = request.remote_addr
            user.login_count = (user.login_count or 0) + 1
        
        # Store NHS tokens securely
        user.nhs_access_token = security_manager.encrypt_data(token_data['access_token'])
        if 'refresh_token' in token_data:
            user.nhs_refresh_token = security_manager.encrypt_data(token_data['refresh_token'])
        
        # Reset failed login attempts
        user.failed_login_attempts = 0
        user.account_locked_until = None
        
        db.session.commit()
        
        # Create application session
        session_id = session_manager.create_session(
            user.id, 
            request.remote_addr, 
            request.headers.get('User-Agent', '')
        )
        
        # Generate application tokens
        access_token = create_access_token(
            identity=user.id,
            additional_claims={
                'session_id': session_id,
                'nhs_authenticated': True,
                'organisation_code': organisation_code
            }
        )
        refresh_token = create_refresh_token(identity=user.id)
        
        audit_logger.log_security_event(
            event_type='nhs_login_success',
            user_id=user.id,
            ip_address=request.remote_addr,
            details='NHS CIS2 authentication completed successfully'
        )
        
        return jsonify({
            'message': 'NHS authentication successful',
            'user': {
                'id': user.id,
                'email': user.email,
                'first_name': user.first_name,
                'last_name': user.last_name,
                'role': user.role,
                'organisation_code': user.organisation_code,
                'nhs_number': NHS_Data_Standards.format_nhs_number(user.nhs_number) if user.nhs_number else None
            },
            'access_token': access_token,
            'refresh_token': refresh_token,
            'session_expires_at': (datetime.utcnow() + timedelta(
                minutes=current_app.config.get('SESSION_TIMEOUT_MINUTES', 120)
            )).isoformat()
        }), 200
        
    except Exception as e:
        logger.error(f'NHS CIS2 callback error: {str(e)}')
        audit_logger.log_security_event(
            event_type='nhs_login_failed',
            user_id=None,
            ip_address=request.remote_addr,
            details=f'NHS CIS2 authentication failed: {str(e)}'
        )
        return jsonify({'error': 'NHS authentication failed'}), 500

@auth_bp.route('/nhs-cis2/refresh', methods=['POST'])
@jwt_required()
def nhs_cis2_refresh():
    """Refresh NHS CIS2 tokens"""
    try:
        user_id = get_jwt_identity()
        user = User.query.get(user_id)
        
        if not user or not user.nhs_refresh_token:
            return jsonify({'error': 'NHS refresh token not found'}), 404
        
        # Decrypt stored refresh token
        refresh_token = security_manager.decrypt_data(user.nhs_refresh_token)
        
        nhs_client = create_nhs_cis2_client()
        token_data = nhs_client.refresh_token(refresh_token)
        
        # Update stored tokens
        user.nhs_access_token = security_manager.encrypt_data(token_data['access_token'])
        if 'refresh_token' in token_data:
            user.nhs_refresh_token = security_manager.encrypt_data(token_data['refresh_token'])
        
        db.session.commit()
        
        return jsonify({
            'message': 'NHS tokens refreshed successfully',
            'expires_in': token_data.get('expires_in', 3600)
        }), 200
        
    except Exception as e:
        logger.error(f'NHS token refresh error: {str(e)}')
        return jsonify({'error': 'Failed to refresh NHS tokens'}), 500

@auth_bp.route('/nhs-cis2/logout', methods=['POST'])
@jwt_required()
def nhs_cis2_logout():
    """Logout from NHS CIS2 and application"""
    try:
        user_id = get_jwt_identity()
        user = User.query.get(user_id)
        
        if user:
            # Clear NHS tokens
            user.nhs_access_token = None
            user.nhs_refresh_token = None
            user.session_token = None
            user.session_expires = None
            
            db.session.commit()
            
            audit_logger.log_security_event(
                event_type='nhs_logout',
                user_id=user.id,
                ip_address=request.remote_addr,
                details='NHS CIS2 logout completed'
            )
        
        # Invalidate session
        session_manager.invalidate_session(user_id)
        
        return jsonify({'message': 'Logout successful'}), 200
        
    except Exception as e:
        logger.error(f'NHS logout error: {str(e)}')
        return jsonify({'error': 'Logout failed'}), 500
