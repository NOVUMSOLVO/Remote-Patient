"""
Authentication API endpoints.
"""
from flask import Blueprint, request, jsonify
from flask_jwt_extended import (
    create_access_token,
    create_refresh_token,
    jwt_required,
    get_jwt_identity
)
from app.models.user import User
from app.services.auth_service import verify_otp
from app import db

auth_bp = Blueprint('auth', __name__)

@auth_bp.route('/login', methods=['POST'])
def login():
    """User login endpoint."""
    data = request.get_json()
    
    if not data:
        return jsonify({"msg": "Missing JSON in request"}), 400
        
    email = data.get('email', None)
    password = data.get('password', None)
    otp = data.get('otp', None)
    
    if not email or not password:
        return jsonify({"msg": "Missing email or password"}), 400
    
    user = User.query.filter_by(email=email).first()
    if not user or not user.check_password(password):
        return jsonify({"msg": "Invalid email or password"}), 401
    
    if user.otp_secret and not otp:
        return jsonify({
            "msg": "2FA required",
            "requires_2fa": True
        }), 200
    
    if user.otp_secret and not verify_otp(user.otp_secret, otp):
        return jsonify({"msg": "Invalid 2FA code"}), 401
    
    # Create tokens
    access_token = create_access_token(identity=user.id)
    refresh_token = create_refresh_token(identity=user.id)
    
    return jsonify(
        access_token=access_token,
        refresh_token=refresh_token,
        user={
            "id": user.id,
            "email": user.email,
            "name": f"{user.first_name} {user.last_name}",
            "role": user.role
        }
    ), 200

@auth_bp.route('/refresh', methods=['POST'])
@jwt_required(refresh=True)
def refresh():
    """Refresh access token using refresh token."""
    current_user_id = get_jwt_identity()
    access_token = create_access_token(identity=current_user_id)
    
    return jsonify(access_token=access_token), 200

@auth_bp.route('/me', methods=['GET'])
@jwt_required()
def me():
    """Get current user information."""
    current_user_id = get_jwt_identity()
    user = User.query.get(current_user_id)
    
    if not user:
        return jsonify({"msg": "User not found"}), 404
    
    return jsonify({
        "id": user.id,
        "email": user.email,
        "name": f"{user.first_name} {user.last_name}",
        "role": user.role
    }), 200