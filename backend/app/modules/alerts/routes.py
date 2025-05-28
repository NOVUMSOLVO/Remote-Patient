"""
Alerts and Notifications Module
Rule-based condition monitoring and triggered interventions notifications
"""

from flask import Blueprint, request, jsonify, current_app
from flask_jwt_extended import jwt_required, get_jwt_identity
from datetime import datetime, timedelta
from sqlalchemy import and_, desc, or_

from app import db
from app.models import Alert, AlertSeverity, HealthRecord, PatientProfile, User, Device
from app.utils.notification_service import NotificationService
from app.utils.rule_engine import RuleEngine
from app.utils.websocket_service import get_websocket_service

alerts_bp = Blueprint('alerts', __name__)

@alerts_bp.route('/', methods=['GET'])
@jwt_required()
def get_alerts():
    """Get alerts for the current user"""
    try:
        user_id = get_jwt_identity()
        user = User.query.get(user_id)
        
        if not user:
            return jsonify({'error': 'User not found'}), 404
        
        # Get query parameters
        page = int(request.args.get('page', 1))
        per_page = min(int(request.args.get('per_page', 20)), 100)
        severity = request.args.get('severity')
        is_resolved = request.args.get('is_resolved')
        
        # Build query based on user role
        if user.role.value == 'patient':
            if not user.patient_profile:
                return jsonify({'error': 'Patient profile not found'}), 404
            query = Alert.query.filter_by(patient_id=user.patient_profile.id)
        else:
            # Healthcare providers can see alerts for their patients
            query = Alert.query.join(PatientProfile).join(User)
        
        # Apply filters
        if severity:
            try:
                severity_enum = AlertSeverity(severity)
                query = query.filter(Alert.severity == severity_enum)
            except ValueError:
                return jsonify({'error': 'Invalid severity level'}), 400
        
        if is_resolved is not None:
            is_resolved_bool = is_resolved.lower() in ['true', '1', 'yes']
            query = query.filter(Alert.is_resolved == is_resolved_bool)
        
        # Order by creation date (newest first)
        query = query.order_by(desc(Alert.created_at))
        
        # Paginate
        paginated_alerts = query.paginate(
            page=page,
            per_page=per_page,
            error_out=False
        )
        
        # Format alerts
        alerts = []
        for alert in paginated_alerts.items:
            alert_data = {
                'id': alert.id,
                'alert_type': alert.alert_type,
                'severity': alert.severity.value,
                'title': alert.title,
                'message': alert.message,
                'is_read': alert.is_read,
                'is_resolved': alert.is_resolved,
                'created_at': alert.created_at.isoformat(),
                'resolved_at': alert.resolved_at.isoformat() if alert.resolved_at else None
            }
            
            # Add patient info for healthcare providers
            if user.role.value != 'patient':
                patient = alert.patient.user
                alert_data['patient'] = {
                    'id': patient.id,
                    'name': f"{patient.first_name} {patient.last_name}",
                    'nhs_number': patient.nhs_number
                }
            
            alerts.append(alert_data)
        
        return jsonify({
            'alerts': alerts,
            'pagination': {
                'page': page,
                'per_page': per_page,
                'total': paginated_alerts.total,
                'pages': paginated_alerts.pages,
                'has_next': paginated_alerts.has_next,
                'has_prev': paginated_alerts.has_prev
            }
        }), 200
        
    except Exception as e:
        current_app.logger.error(f'Get alerts error: {str(e)}')
        return jsonify({'error': 'Failed to retrieve alerts'}), 500

@alerts_bp.route('/<int:alert_id>/read', methods=['POST'])
@jwt_required()
def mark_alert_read(alert_id):
    """Mark alert as read"""
    try:
        user_id = get_jwt_identity()
        user = User.query.get(user_id)
        
        if not user:
            return jsonify({'error': 'User not found'}), 404
        
        # Get alert with permission check
        if user.role.value == 'patient':
            if not user.patient_profile:
                return jsonify({'error': 'Patient profile not found'}), 404
            alert = Alert.query.filter_by(id=alert_id, patient_id=user.patient_profile.id).first()
        else:
            alert = Alert.query.get(alert_id)
        
        if not alert:
            return jsonify({'error': 'Alert not found'}), 404
        
        alert.is_read = True
        db.session.commit()
        
        # Broadcast acknowledgment via WebSocket
        websocket_service = get_websocket_service()
        try:
            if websocket_service:
                websocket_service.broadcast_alert_update('alert_acknowledged', {
                    'alert_id': alert_id,
                    'acknowledged_by': user_id,
                    'timestamp': datetime.utcnow().isoformat()
                }, 'alerts_general')
                
        except Exception as e:
            current_app.logger.error(f'Failed to broadcast alert acknowledgment via WebSocket: {str(e)}')
        
        return jsonify({'message': 'Alert marked as read'}), 200
        
    except Exception as e:
        db.session.rollback()
        current_app.logger.error(f'Mark alert read error: {str(e)}')
        return jsonify({'error': 'Failed to mark alert as read'}), 500

@alerts_bp.route('/<int:alert_id>/resolve', methods=['POST'])
@jwt_required()
def resolve_alert(alert_id):
    """Resolve an alert (healthcare providers only)"""
    try:
        user_id = get_jwt_identity()
        user = User.query.get(user_id)
        
        if not user:
            return jsonify({'error': 'User not found'}), 404
        
        # Only healthcare providers can resolve alerts
        if user.role.value == 'patient':
            return jsonify({'error': 'Insufficient permissions'}), 403
        
        alert = Alert.query.get(alert_id)
        if not alert:
            return jsonify({'error': 'Alert not found'}), 404
        
        if alert.is_resolved:
            return jsonify({'error': 'Alert already resolved'}), 400
        
        alert.is_resolved = True
        alert.resolved_at = datetime.utcnow()
        alert.resolved_by = user_id
        
        db.session.commit()
        
        # Send notification to patient and broadcast via WebSocket
        notification_service = NotificationService()
        websocket_service = get_websocket_service()
        
        try:
            notification_service.send_alert_resolution_notification(alert, user)
        except Exception as e:
            current_app.logger.error(f'Failed to send resolution notification: {str(e)}')
        
        # Broadcast alert resolution via WebSocket
        try:
            if websocket_service:
                alert_data = {
                    'id': alert.id,
                    'type': alert.alert_type,
                    'severity': alert.severity.value,
                    'title': alert.title,
                    'message': alert.message,
                    'patient_id': alert.patient_id,
                    'resolved': True,
                    'resolved_at': alert.resolved_at.isoformat(),
                    'resolved_by': user_id
                }
                
                # Broadcast resolution to alerts room
                websocket_service.broadcast_alert_update('alert_resolved', alert_data, 'alerts_general')
                
                # Notify patient
                websocket_service.send_user_notification(
                    alert.patient.user.id,
                    {
                        'type': 'alert_resolved',
                        'alert': alert_data,
                        'resolved_by_name': f"{user.first_name} {user.last_name}"
                    }
                )
                
        except Exception as e:
            current_app.logger.error(f'Failed to broadcast alert resolution via WebSocket: {str(e)}')
        
        return jsonify({'message': 'Alert resolved successfully'}), 200
        
    except Exception as e:
        db.session.rollback()
        current_app.logger.error(f'Resolve alert error: {str(e)}')
        return jsonify({'error': 'Failed to resolve alert'}), 500

@alerts_bp.route('/rules', methods=['GET'])
@jwt_required()
def get_alert_rules():
    """Get alert rules for the current patient"""
    try:
        user_id = get_jwt_identity()
        user = User.query.get(user_id)
        
        if not user or not user.patient_profile:
            return jsonify({'error': 'Patient profile not found'}), 404
        
        rule_engine = RuleEngine()
        rules = rule_engine.get_patient_rules(user.patient_profile.id)
        
        return jsonify({'rules': rules}), 200
        
    except Exception as e:
        current_app.logger.error(f'Get alert rules error: {str(e)}')
        return jsonify({'error': 'Failed to retrieve alert rules'}), 500

@alerts_bp.route('/check', methods=['POST'])
@jwt_required()
def check_alert_conditions():
    """Check alert conditions for new health data"""
    try:
        user_id = get_jwt_identity()
        user = User.query.get(user_id)
        
        if not user or not user.patient_profile:
            return jsonify({'error': 'Patient profile not found'}), 404
        
        data = request.get_json()
        health_record_id = data.get('health_record_id')
        
        if not health_record_id:
            return jsonify({'error': 'health_record_id is required'}), 400
        
        health_record = HealthRecord.query.filter_by(
            id=health_record_id,
            patient_id=user.patient_profile.id
        ).first()
        
        if not health_record:
            return jsonify({'error': 'Health record not found'}), 404
        
        # Check alert conditions
        rule_engine = RuleEngine()
        triggered_alerts = rule_engine.evaluate_health_record(health_record)
        
        created_alerts = []
        for alert_data in triggered_alerts:
            alert = Alert(
                patient_id=user.patient_profile.id,
                health_record_id=health_record.id,
                alert_type=alert_data['type'],
                severity=AlertSeverity(alert_data['severity']),
                title=alert_data['title'],
                message=alert_data['message']
            )
            
            db.session.add(alert)
            created_alerts.append(alert)
        
        db.session.commit()
        
        # Send notifications for critical alerts and broadcast via WebSocket
        notification_service = NotificationService()
        websocket_service = get_websocket_service()
        
        for alert in created_alerts:
            if alert.severity in [AlertSeverity.HIGH, AlertSeverity.CRITICAL]:
                try:
                    notification_service.send_alert_notification(alert)
                except Exception as e:
                    current_app.logger.error(f'Failed to send alert notification: {str(e)}')
            
            # Broadcast alert via WebSocket for real-time updates
            try:
                alert_data = {
                    'id': alert.id,
                    'type': alert.alert_type,
                    'severity': alert.severity.value,
                    'title': alert.title,
                    'message': alert.message,
                    'patient_id': alert.patient_id,
                    'created_at': alert.created_at.isoformat(),
                    'acknowledged': alert.is_read,
                    'resolved': alert.is_resolved
                }
                
                if websocket_service:
                    # Broadcast to general alerts room
                    websocket_service.broadcast_alert(alert_data, 'alerts_general')
                    
                    # Send to specific patient's healthcare providers
                    websocket_service.send_user_notification(
                        alert.patient.user.id, 
                        {
                            'type': 'new_alert',
                            'alert': alert_data
                        }
                    )
                    
            except Exception as e:
                current_app.logger.error(f'Failed to broadcast alert via WebSocket: {str(e)}')
        
        return jsonify({
            'message': f'{len(created_alerts)} alerts created',
            'alerts': [{
                'id': alert.id,
                'type': alert.alert_type,
                'severity': alert.severity.value,
                'title': alert.title,
                'message': alert.message
            } for alert in created_alerts]
        }), 200
        
    except Exception as e:
        db.session.rollback()
        current_app.logger.error(f'Check alert conditions error: {str(e)}')
        return jsonify({'error': 'Failed to check alert conditions'}), 500

@alerts_bp.route('/summary', methods=['GET'])
@jwt_required()
def get_alerts_summary():
    """Get summary of alerts"""
    try:
        user_id = get_jwt_identity()
        user = User.query.get(user_id)
        
        if not user:
            return jsonify({'error': 'User not found'}), 404
        
        # Build base query
        if user.role.value == 'patient':
            if not user.patient_profile:
                return jsonify({'error': 'Patient profile not found'}), 404
            base_query = Alert.query.filter_by(patient_id=user.patient_profile.id)
        else:
            base_query = Alert.query
        
        # Get counts by severity
        severity_counts = {}
        for severity in AlertSeverity:
            count = base_query.filter_by(severity=severity, is_resolved=False).count()
            severity_counts[severity.value] = count
        
        # Get recent unread alerts count
        unread_count = base_query.filter_by(is_read=False, is_resolved=False).count()
        
        # Get resolved alerts in last 24 hours
        yesterday = datetime.utcnow() - timedelta(days=1)
        recently_resolved = base_query.filter(
            and_(
                Alert.is_resolved == True,
                Alert.resolved_at >= yesterday
            )
        ).count()
        
        return jsonify({
            'severity_counts': severity_counts,
            'unread_count': unread_count,
            'recently_resolved': recently_resolved,
            'total_active': sum(severity_counts.values())
        }), 200
        
    except Exception as e:
        current_app.logger.error(f'Get alerts summary error: {str(e)}')
        return jsonify({'error': 'Failed to retrieve alerts summary'}), 500

@alerts_bp.route('/<int:alert_id>/actions', methods=['POST'])
@jwt_required()
def execute_alert_action(alert_id):
    """Execute an action on an alert"""
    try:
        user_id = get_jwt_identity()
        user = User.query.get(user_id)
        
        if not user:
            return jsonify({'error': 'User not found'}), 404
        
        # Get the action from request body
        data = request.get_json()
        action = data.get('action')
        
        if not action:
            return jsonify({'error': 'Action is required'}), 400
        
        alert = Alert.query.get(alert_id)
        if not alert:
            return jsonify({'error': 'Alert not found'}), 404
        
        # Check permissions
        if user.role.value == 'patient':
            # Patients can only acknowledge their own alerts
            if not user.patient_profile or alert.patient_id != user.patient_profile.id:
                return jsonify({'error': 'Insufficient permissions'}), 403
            if action not in ['acknowledge']:
                return jsonify({'error': 'Action not allowed for patients'}), 403
        
        websocket_service = get_websocket_service()
        
        # Execute the action
        if action == 'acknowledge':
            alert.is_read = True
            db.session.commit()
            
            # Broadcast acknowledgment
            if websocket_service:
                websocket_service.broadcast_alert_update('alert_acknowledged', {
                    'alert_id': alert_id,
                    'acknowledged_by': user_id,
                    'timestamp': datetime.utcnow().isoformat()
                }, 'alerts_general')
            
            return jsonify({'message': 'Alert acknowledged successfully'}), 200
            
        elif action == 'escalate_to_gp':
            # Only healthcare providers can escalate
            if user.role.value == 'patient':
                return jsonify({'error': 'Insufficient permissions'}), 403
            
            # Update alert priority/escalation level
            alert.escalation_level = getattr(alert, 'escalation_level', 0) + 1
            db.session.commit()
            
            # Send escalation notification
            notification_service = NotificationService()
            try:
                notification_service.send_escalation_notification(alert, user)
            except Exception as e:
                current_app.logger.error(f'Failed to send escalation notification: {str(e)}')
            
            # Broadcast escalation
            if websocket_service:
                websocket_service.broadcast_alert_update('alert_escalated', {
                    'alert_id': alert_id,
                    'escalated_by': user_id,
                    'escalation_level': alert.escalation_level,
                    'timestamp': datetime.utcnow().isoformat()
                }, 'alerts_general')
            
            return jsonify({'message': 'Alert escalated successfully'}), 200
            
        elif action == 'contact_patient':
            # Log the contact attempt
            current_app.logger.info(f'Contact patient action for alert {alert_id} by user {user_id}')
            
            # Broadcast contact action
            if websocket_service:
                websocket_service.broadcast_alert_update('patient_contacted', {
                    'alert_id': alert_id,
                    'contacted_by': user_id,
                    'timestamp': datetime.utcnow().isoformat()
                }, 'alerts_general')
            
            return jsonify({'message': 'Patient contact logged successfully'}), 200
            
        elif action == 'schedule_appointment':
            # This would integrate with appointment scheduling system
            current_app.logger.info(f'Schedule appointment action for alert {alert_id} by user {user_id}')
            
            # Broadcast appointment scheduling
            if websocket_service:
                websocket_service.broadcast_alert_update('appointment_scheduled', {
                    'alert_id': alert_id,
                    'scheduled_by': user_id,
                    'timestamp': datetime.utcnow().isoformat()
                }, 'alerts_general')
            
            return jsonify({'message': 'Appointment scheduling initiated'}), 200
            
        else:
            return jsonify({'error': 'Unknown action'}), 400
        
    except Exception as e:
        db.session.rollback()
        current_app.logger.error(f'Execute alert action error: {str(e)}')
        return jsonify({'error': 'Failed to execute action'}), 500
