"""
Patient management API endpoints.
"""
from flask import Blueprint, request, jsonify
from flask_jwt_extended import jwt_required, get_jwt_identity
from datetime import datetime

from app.models.patient import Patient
from app.models.user import User
from app import db

patients_bp = Blueprint('patients', __name__)


@patients_bp.route('/', methods=['GET'])
@jwt_required()
def get_patients():
    """Get all patients."""
    # In a real app, you would filter by the provider-patient relationship
    patients = Patient.query.all()
    
    result = []
    for patient in patients:
        result.append({
            "id": patient.id,
            "first_name": patient.first_name,
            "last_name": patient.last_name,
            "date_of_birth": patient.date_of_birth.isoformat() if patient.date_of_birth else None,
            "gender": patient.gender,
            "email": patient.email,
            "phone": patient.phone
        })
    
    return jsonify(result), 200


@patients_bp.route('/<int:patient_id>', methods=['GET'])
@jwt_required()
def get_patient(patient_id):
    """Get a specific patient."""
    patient = Patient.query.get(patient_id)
    
    if not patient:
        return jsonify({"msg": "Patient not found"}), 404
    
    result = {
        "id": patient.id,
        "first_name": patient.first_name,
        "last_name": patient.last_name,
        "date_of_birth": patient.date_of_birth.isoformat() if patient.date_of_birth else None,
        "gender": patient.gender,
        "email": patient.email,
        "phone": patient.phone,
        "address": patient.address,
        "emergency_contact_name": patient.emergency_contact_name,
        "emergency_contact_phone": patient.emergency_contact_phone,
        "created_at": patient.created_at.isoformat(),
        "updated_at": patient.updated_at.isoformat()
    }
    
    return jsonify(result), 200


@patients_bp.route('/', methods=['POST'])
@jwt_required()
def create_patient():
    """Create a new patient."""
    data = request.get_json()
    
    if not data:
        return jsonify({"msg": "Missing JSON in request"}), 400
    
    # Required fields
    required_fields = ['first_name', 'last_name', 'date_of_birth', 'gender']
    for field in required_fields:
        if field not in data:
            return jsonify({"msg": f"Missing required field: {field}"}), 400
    
    try:
        # Parse date of birth
        dob = datetime.fromisoformat(data['date_of_birth'].replace('Z', '+00:00')).date()
        
        # Create new patient
        patient = Patient(
            first_name=data['first_name'],
            last_name=data['last_name'],
            date_of_birth=dob,
            gender=data['gender'],
            email=data.get('email'),
            phone=data.get('phone'),
            address=data.get('address'),
            emergency_contact_name=data.get('emergency_contact_name'),
            emergency_contact_phone=data.get('emergency_contact_phone')
        )
        
        db.session.add(patient)
        db.session.commit()
        
        # In a real app, you would also create a provider-patient relationship here
        
        return jsonify({
            "msg": "Patient created successfully",
            "id": patient.id
        }), 201
        
    except ValueError:
        return jsonify({"msg": "Invalid date format for date_of_birth"}), 400
    except Exception as e:
        db.session.rollback()
        return jsonify({"msg": f"Error creating patient: {str(e)}"}), 500


@patients_bp.route('/<int:patient_id>', methods=['PUT'])
@jwt_required()
def update_patient(patient_id):
    """Update a patient's information."""
    patient = Patient.query.get(patient_id)
    
    if not patient:
        return jsonify({"msg": "Patient not found"}), 404
    
    data = request.get_json()
    
    if not data:
        return jsonify({"msg": "Missing JSON in request"}), 400
    
    try:
        # Update fields if provided
        if 'first_name' in data:
            patient.first_name = data['first_name']
        
        if 'last_name' in data:
            patient.last_name = data['last_name']
        
        if 'date_of_birth' in data:
            patient.date_of_birth = datetime.fromisoformat(data['date_of_birth'].replace('Z', '+00:00')).date()
        
        if 'gender' in data:
            patient.gender = data['gender']
        
        if 'email' in data:
            patient.email = data['email']
        
        if 'phone' in data:
            patient.phone = data['phone']
        
        if 'address' in data:
            patient.address = data['address']
        
        if 'emergency_contact_name' in data:
            patient.emergency_contact_name = data['emergency_contact_name']
        
        if 'emergency_contact_phone' in data:
            patient.emergency_contact_phone = data['emergency_contact_phone']
        
        patient.updated_at = datetime.utcnow()
        db.session.commit()
        
        return jsonify({"msg": "Patient updated successfully"}), 200
        
    except ValueError:
        return jsonify({"msg": "Invalid date format for date_of_birth"}), 400
    except Exception as e:
        db.session.rollback()
        return jsonify({"msg": f"Error updating patient: {str(e)}"}), 500


@patients_bp.route('/<int:patient_id>', methods=['DELETE'])
@jwt_required()
def delete_patient(patient_id):
    """Delete a patient."""
    patient = Patient.query.get(patient_id)
    
    if not patient:
        return jsonify({"msg": "Patient not found"}), 404
    
    try:
        db.session.delete(patient)
        db.session.commit()
        
        return jsonify({"msg": "Patient deleted successfully"}), 200
        
    except Exception as e:
        db.session.rollback()
        return jsonify({"msg": f"Error deleting patient: {str(e)}"}), 500