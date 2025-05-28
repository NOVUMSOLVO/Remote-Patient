"""
Real-Time Monitoring Module
Interactive dashboards for data visualization
"""

from flask import Blueprint, request, jsonify, current_app
from flask_jwt_extended import jwt_required, get_jwt_identity
from datetime import datetime, timedelta
from sqlalchemy import and_, desc, func
import json

from app import db
from app.models import HealthRecord, Device, PatientProfile, User, Alert
from app.utils.data_analysis import calculate_trends, detect_anomalies
from app.utils.real_time import get_real_time_data, subscribe_to_updates

monitoring_bp = Blueprint('monitoring', __name__)

@monitoring_bp.route('/dashboard', methods=['GET'])
@jwt_required()
def get_dashboard_data():
    """Get comprehensive dashboard data for patient"""
    try:
        user_id = get_jwt_identity()
        user = User.query.get(user_id)
        
        if not user or not user.patient_profile:
            return jsonify({'error': 'Patient profile not found'}), 404
        
        # Get query parameters
        timeframe = request.args.get('timeframe', '7d')  # 1d, 7d, 30d, 90d
        
        # Calculate date range
        end_date = datetime.utcnow()
        if timeframe == '1d':
            start_date = end_date - timedelta(days=1)
        elif timeframe == '7d':
            start_date = end_date - timedelta(days=7)
        elif timeframe == '30d':
            start_date = end_date - timedelta(days=30)
        elif timeframe == '90d':
            start_date = end_date - timedelta(days=90)
        else:
            start_date = end_date - timedelta(days=7)
        
        # Get health records
        health_records = HealthRecord.query.filter(
            and_(
                HealthRecord.patient_id == user.patient_profile.id,
                HealthRecord.timestamp >= start_date,
                HealthRecord.timestamp <= end_date
            )
        ).order_by(desc(HealthRecord.timestamp)).all()
        
        # Get active devices
        active_devices = Device.query.filter_by(
            patient_id=user.patient_profile.id,
            is_active=True
        ).all()
        
        # Get recent alerts
        recent_alerts = Alert.query.filter(
            and_(
                Alert.patient_id == user.patient_profile.id,
                Alert.created_at >= start_date
            )
        ).order_by(desc(Alert.created_at)).limit(10).all()
        
        # Process data by type
        data_by_type = {}
        for record in health_records:
            if record.record_type not in data_by_type:
                data_by_type[record.record_type] = []
            
            data_by_type[record.record_type].append({
                'id': record.id,
                'value': record.value,
                'unit': record.unit,
                'timestamp': record.timestamp.isoformat(),
                'device_name': record.device.device_name if record.device else 'Manual Entry',
                'notes': record.notes
            })
        
        # Calculate vital statistics
        vital_stats = calculate_vital_statistics(data_by_type, timeframe)
        
        # Get trend analysis
        trends = {}
        for record_type, records in data_by_type.items():
            if len(records) > 1:
                trends[record_type] = calculate_trends(records)
        
        # Check for anomalies
        anomalies = {}
        for record_type, records in data_by_type.items():
            anomaly_result = detect_anomalies(record_type, records, user.patient_profile)
            if anomaly_result['anomalies']:
                anomalies[record_type] = anomaly_result
        
        dashboard_data = {
            'patient_info': {
                'name': f"{user.first_name} {user.last_name}",
                'nhs_number': user.nhs_number,
                'age': calculate_age(user.patient_profile.date_of_birth) if user.patient_profile.date_of_birth else None
            },
            'timeframe': timeframe,
            'data_summary': {
                'total_records': len(health_records),
                'record_types': list(data_by_type.keys()),
                'active_devices': len(active_devices),
                'recent_alerts': len(recent_alerts)
            },
            'vital_statistics': vital_stats,
            'health_data': data_by_type,
            'trends': trends,
            'anomalies': anomalies,
            'devices': [{
                'id': device.id,
                'name': device.device_name,
                'type': device.device_type.value,
                'last_sync': device.last_sync.isoformat() if device.last_sync else None,
                'status': 'active' if device.is_active else 'inactive'
            } for device in active_devices],
            'recent_alerts': [{
                'id': alert.id,
                'type': alert.alert_type,
                'severity': alert.severity.value,
                'title': alert.title,
                'message': alert.message,
                'created_at': alert.created_at.isoformat(),
                'is_resolved': alert.is_resolved
            } for alert in recent_alerts]
        }
        
        return jsonify(dashboard_data), 200
        
    except Exception as e:
        current_app.logger.error(f'Dashboard data error: {str(e)}')
        return jsonify({'error': 'Failed to retrieve dashboard data'}), 500

@monitoring_bp.route('/real-time/<record_type>', methods=['GET'])
@jwt_required()
def get_real_time_monitoring(record_type):
    """Get real-time monitoring data for specific record type"""
    try:
        user_id = get_jwt_identity()
        user = User.query.get(user_id)
        
        if not user or not user.patient_profile:
            return jsonify({'error': 'Patient profile not found'}), 404
        
        # Get the last hour of data for real-time monitoring
        start_time = datetime.utcnow() - timedelta(hours=1)
        
        real_time_data = HealthRecord.query.filter(
            and_(
                HealthRecord.patient_id == user.patient_profile.id,
                HealthRecord.record_type == record_type,
                HealthRecord.timestamp >= start_time
            )
        ).order_by(desc(HealthRecord.timestamp)).all()
        
        # Format data for real-time chart
        chart_data = []
        for record in real_time_data:
            chart_data.append({
                'timestamp': record.timestamp.isoformat(),
                'value': record.value,
                'unit': record.unit
            })
        
        # Get latest reading
        latest_record = HealthRecord.query.filter(
            and_(
                HealthRecord.patient_id == user.patient_profile.id,
                HealthRecord.record_type == record_type
            )
        ).order_by(desc(HealthRecord.timestamp)).first()
        
        latest_reading = None
        if latest_record:
            latest_reading = {
                'value': latest_record.value,
                'unit': latest_record.unit,
                'timestamp': latest_record.timestamp.isoformat(),
                'device': latest_record.device.device_name if latest_record.device else 'Manual'
            }
        
        return jsonify({
            'record_type': record_type,
            'latest_reading': latest_reading,
            'chart_data': chart_data,
            'data_points': len(chart_data),
            'timeframe': '1 hour'
        }), 200
        
    except Exception as e:
        current_app.logger.error(f'Real-time monitoring error: {str(e)}')
        return jsonify({'error': 'Failed to retrieve real-time data'}), 500

@monitoring_bp.route('/historical/<record_type>', methods=['GET'])
@jwt_required()
def get_historical_data(record_type):
    """Get historical data with pagination and filtering"""
    try:
        user_id = get_jwt_identity()
        user = User.query.get(user_id)
        
        if not user or not user.patient_profile:
            return jsonify({'error': 'Patient profile not found'}), 404
        
        # Get query parameters
        page = int(request.args.get('page', 1))
        per_page = min(int(request.args.get('per_page', 50)), 100)  # Max 100 records per page
        start_date = request.args.get('start_date')
        end_date = request.args.get('end_date')
        device_id = request.args.get('device_id')
        
        # Build query
        query = HealthRecord.query.filter(
            and_(
                HealthRecord.patient_id == user.patient_profile.id,
                HealthRecord.record_type == record_type
            )
        )
        
        # Add date filters
        if start_date:
            start_dt = datetime.fromisoformat(start_date)
            query = query.filter(HealthRecord.timestamp >= start_dt)
        
        if end_date:
            end_dt = datetime.fromisoformat(end_date)
            query = query.filter(HealthRecord.timestamp <= end_dt)
        
        # Add device filter
        if device_id:
            query = query.filter(HealthRecord.device_id == int(device_id))
        
        # Order by timestamp descending
        query = query.order_by(desc(HealthRecord.timestamp))
        
        # Paginate
        paginated_records = query.paginate(
            page=page, 
            per_page=per_page, 
            error_out=False
        )
        
        # Format records
        records = []
        for record in paginated_records.items:
            records.append({
                'id': record.id,
                'value': record.value,
                'unit': record.unit,
                'timestamp': record.timestamp.isoformat(),
                'device_name': record.device.device_name if record.device else 'Manual Entry',
                'notes': record.notes,
                'is_validated': record.is_validated
            })
        
        return jsonify({
            'record_type': record_type,
            'records': records,
            'pagination': {
                'page': page,
                'per_page': per_page,
                'total': paginated_records.total,
                'pages': paginated_records.pages,
                'has_next': paginated_records.has_next,
                'has_prev': paginated_records.has_prev
            }
        }), 200
        
    except Exception as e:
        current_app.logger.error(f'Historical data error: {str(e)}')
        return jsonify({'error': 'Failed to retrieve historical data'}), 500

@monitoring_bp.route('/summary', methods=['GET'])
@jwt_required()
def get_monitoring_summary():
    """Get monitoring summary statistics"""
    try:
        user_id = get_jwt_identity()
        user = User.query.get(user_id)
        
        if not user or not user.patient_profile:
            return jsonify({'error': 'Patient profile not found'}), 404
        
        # Get summary for different timeframes
        now = datetime.utcnow()
        timeframes = {
            'today': now.replace(hour=0, minute=0, second=0, microsecond=0),
            'week': now - timedelta(days=7),
            'month': now - timedelta(days=30)
        }
        
        summary = {}
        
        for period, start_date in timeframes.items():
            # Count records by type
            record_counts = db.session.query(
                HealthRecord.record_type,
                func.count(HealthRecord.id).label('count')
            ).filter(
                and_(
                    HealthRecord.patient_id == user.patient_profile.id,
                    HealthRecord.timestamp >= start_date
                )
            ).group_by(HealthRecord.record_type).all()
            
            # Count alerts
            alert_count = Alert.query.filter(
                and_(
                    Alert.patient_id == user.patient_profile.id,
                    Alert.created_at >= start_date
                )
            ).count()
            
            summary[period] = {
                'record_counts': {record_type: count for record_type, count in record_counts},
                'total_records': sum(count for _, count in record_counts),
                'alert_count': alert_count
            }
        
        # Get device status summary
        devices = Device.query.filter_by(patient_id=user.patient_profile.id).all()
        device_summary = {
            'total': len(devices),
            'active': len([d for d in devices if d.is_active]),
            'recently_synced': len([d for d in devices if d.last_sync and d.last_sync > (now - timedelta(days=1))])
        }
        
        return jsonify({
            'summary_by_period': summary,
            'device_summary': device_summary,
            'generated_at': now.isoformat()
        }), 200
        
    except Exception as e:
        current_app.logger.error(f'Monitoring summary error: {str(e)}')
        return jsonify({'error': 'Failed to retrieve monitoring summary'}), 500

def calculate_vital_statistics(data_by_type, timeframe):
    """Calculate vital statistics for dashboard"""
    vital_stats = {}
    
    for record_type, records in data_by_type.items():
        if not records:
            continue
        
        # Extract numeric values
        numeric_values = []
        for record in records:
            if isinstance(record['value'], (int, float)):
                numeric_values.append(record['value'])
            elif isinstance(record['value'], dict):
                # Handle complex measurements like blood pressure
                if 'systolic' in record['value'] and 'diastolic' in record['value']:
                    numeric_values.append({
                        'systolic': record['value']['systolic'],
                        'diastolic': record['value']['diastolic']
                    })
        
        if numeric_values:
            if isinstance(numeric_values[0], dict):
                # Blood pressure or similar complex measurement
                vital_stats[record_type] = {
                    'latest': numeric_values[0],
                    'count': len(numeric_values),
                    'avg_systolic': sum(v['systolic'] for v in numeric_values) / len(numeric_values),
                    'avg_diastolic': sum(v['diastolic'] for v in numeric_values) / len(numeric_values)
                }
            else:
                # Simple numeric measurement
                vital_stats[record_type] = {
                    'latest': numeric_values[0],
                    'average': sum(numeric_values) / len(numeric_values),
                    'min': min(numeric_values),
                    'max': max(numeric_values),
                    'count': len(numeric_values)
                }
    
    return vital_stats

def calculate_age(birth_date):
    """Calculate age from birth date"""
    if not birth_date:
        return None
    
    today = datetime.today().date()
    age = today.year - birth_date.year
    
    if today.month < birth_date.month or (today.month == birth_date.month and today.day < birth_date.day):
        age -= 1
    
    return age
