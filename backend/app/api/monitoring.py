"""
Monitoring API endpoints for patient data management.
"""
from datetime import datetime, timedelta
from flask import Blueprint, request, jsonify
from flask_jwt_extended import jwt_required, get_jwt_identity

from app.models.patient import Patient, PatientMetric
from app.models.user import User
from app.services.monitoring_service import record_patient_metric, get_patient_metrics
from app import db, socketio

monitoring_bp = Blueprint('monitoring', __name__)


@monitoring_bp.route('/metrics/<int:patient_id>', methods=['POST'])
@jwt_required()
def add_metric(patient_id):
    """
    Add a new metric reading for a patient.
    
    Expects JSON with:
    - metric_type: string (e.g., 'heart_rate')
    - value: float
    - unit: string (e.g., 'bpm')
    """
    data = request.get_json()
    
    if not data:
        return jsonify({"msg": "Missing JSON in request"}), 400
        
    metric_type = data.get('metric_type')
    value = data.get('value')
    unit = data.get('unit')
    
    if not metric_type or value is None or not unit:
        return jsonify({"msg": "Missing required fields"}), 400
    
    # Verify patient exists
    patient = Patient.query.get(patient_id)
    if not patient:
        return jsonify({"msg": "Patient not found"}), 404
    
    try:
        # Record the metric and check if it triggers alerts
        metric, alert_sent = record_patient_metric(
            patient_id=patient_id,
            metric_type=metric_type,
            value=float(value),
            unit=unit
        )
        
        response = {
            "msg": "Metric recorded successfully",
            "id": metric.id,
            "alert_sent": alert_sent
        }
        
        return jsonify(response), 201
        
    except Exception as e:
        db.session.rollback()
        return jsonify({"msg": f"Error recording metric: {str(e)}"}), 500


@monitoring_bp.route('/metrics/<int:patient_id>', methods=['GET'])
@jwt_required()
def get_metrics(patient_id):
    """
    Get metrics for a patient, with optional filtering.
    
    Query parameters:
    - metric_type: Filter by metric type
    - hours: Get metrics from the last X hours
    - start_time: ISO datetime string
    - end_time: ISO datetime string
    """
    # Verify patient exists
    patient = Patient.query.get(patient_id)
    if not patient:
        return jsonify({"msg": "Patient not found"}), 404
    
    # Get query parameters
    metric_type = request.args.get('metric_type')
    hours = request.args.get('hours')
    start_time_str = request.args.get('start_time')
    end_time_str = request.args.get('end_time')
    
    # Calculate time range
    start_time = None
    end_time = None
    
    if hours:
        try:
            hours = int(hours)
            start_time = datetime.utcnow() - timedelta(hours=hours)
        except ValueError:
            return jsonify({"msg": "Invalid hours parameter"}), 400
    
    if start_time_str:
        try:
            start_time = datetime.fromisoformat(start_time_str.replace('Z', '+00:00'))
        except ValueError:
            return jsonify({"msg": "Invalid start_time format"}), 400
    
    if end_time_str:
        try:
            end_time = datetime.fromisoformat(end_time_str.replace('Z', '+00:00'))
        except ValueError:
            return jsonify({"msg": "Invalid end_time format"}), 400
    
    # Get metrics
    metrics = get_patient_metrics(
        patient_id=patient_id,
        metric_type=metric_type,
        start_time=start_time,
        end_time=end_time
    )
    
    # Format response
    result = []
    for metric in metrics:
        result.append({
            "id": metric.id,
            "metric_type": metric.metric_type,
            "value": metric.value,
            "unit": metric.unit,
            "timestamp": metric.timestamp.isoformat()
        })
    
    return jsonify(result), 200


@socketio.on('connect', namespace='/monitoring')
def connect():
    """Handle client connection to the monitoring namespace."""
    print('Client connected to monitoring namespace')


@socketio.on('disconnect', namespace='/monitoring')
def disconnect():
    """Handle client disconnection from the monitoring namespace."""
    print('Client disconnected from monitoring namespace')


@socketio.on('subscribe', namespace='/monitoring')
def handle_subscribe(data):
    """
    Subscribe to patient monitoring updates.
    
    Expects:
    - patient_id: ID of the patient to monitor
    """
    if 'patient_id' in data:
        patient_id = data['patient_id']
        room = f'patient_{patient_id}'
        socketio.join_room(room)
        socketio.emit('subscribed', {"patient_id": patient_id}, room=request.sid)
        print(f'Client subscribed to patient {patient_id}')
    else:
        socketio.emit('error', {"msg": "Missing patient_id parameter"}, room=request.sid)