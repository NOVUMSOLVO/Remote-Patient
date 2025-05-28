"""
Admin/Management Module for Remote Patient Monitoring
Provides system administration and management capabilities
"""

from flask import Blueprint, request, jsonify, current_app
from flask_jwt_extended import jwt_required, get_jwt_identity
from sqlalchemy import func, text
from sqlalchemy.exc import IntegrityError
from app.models import (
    db, User, PatientProfile, HealthcareProvider, Device, HealthRecord,
    Alert, Appointment, Message, Report, UserRole, AlertSeverity,
    DeviceType, AppointmentStatus
)
from app.modules.rbac.routes import admin_required
from datetime import datetime, timedelta
import logging

admin_bp = Blueprint('admin', __name__, url_prefix='/api/admin')
logger = logging.getLogger(__name__)

@admin_bp.route('/dashboard', methods=['GET'])
@jwt_required()
@admin_required
def get_admin_dashboard():
    """Get comprehensive admin dashboard statistics"""
    try:
        # User statistics
        total_users = User.query.count()
        active_users = User.query.filter_by(is_active=True).count()
        patients_count = User.query.filter_by(role=UserRole.PATIENT).count()
        providers_count = User.query.filter_by(role=UserRole.HEALTHCARE_PROVIDER).count()
        
        # User registration trends (last 30 days)
        thirty_days_ago = datetime.utcnow() - timedelta(days=30)
        new_users_30d = User.query.filter(User.created_at >= thirty_days_ago).count()
        
        # Device statistics
        total_devices = Device.query.count()
        active_devices = Device.query.filter_by(is_active=True).count()
        device_types_stats = db.session.query(
            Device.device_type,
            func.count(Device.id).label('count')
        ).group_by(Device.device_type).all()
        
        # Health records statistics
        total_records = HealthRecord.query.count()
        records_last_24h = HealthRecord.query.filter(
            HealthRecord.recorded_at >= datetime.utcnow() - timedelta(hours=24)
        ).count()
        
        # Alert statistics
        total_alerts = Alert.query.count()
        active_alerts = Alert.query.filter_by(resolved=False).count()
        critical_alerts = Alert.query.filter(
            Alert.severity == AlertSeverity.CRITICAL,
            Alert.resolved == False
        ).count()
        
        alert_severity_stats = db.session.query(
            Alert.severity,
            func.count(Alert.id).label('count')
        ).filter_by(resolved=False).group_by(Alert.severity).all()
        
        # Appointment statistics
        total_appointments = Appointment.query.count()
        upcoming_appointments = Appointment.query.filter(
            Appointment.scheduled_time >= datetime.utcnow(),
            Appointment.status == AppointmentStatus.SCHEDULED
        ).count()
        
        # Message statistics
        total_messages = Message.query.count()
        messages_last_24h = Message.query.filter(
            Message.timestamp >= datetime.utcnow() - timedelta(hours=24)
        ).count()
        
        # System health checks
        database_status = "healthy"  # This would include actual health checks
        storage_usage = 0  # This would include actual storage metrics
        
        # Provider verification statistics
        verified_providers = HealthcareProvider.query.filter_by(verified=True).count()
        pending_verification = HealthcareProvider.query.filter_by(verified=False).count()
        
        return jsonify({
            'user_statistics': {
                'total_users': total_users,
                'active_users': active_users,
                'patients_count': patients_count,
                'providers_count': providers_count,
                'new_users_30d': new_users_30d,
                'user_activity_rate': round((active_users / total_users * 100) if total_users > 0 else 0, 2)
            },
            'device_statistics': {
                'total_devices': total_devices,
                'active_devices': active_devices,
                'device_types': [
                    {'type': dt.value, 'count': count} for dt, count in device_types_stats
                ],
                'device_activity_rate': round((active_devices / total_devices * 100) if total_devices > 0 else 0, 2)
            },
            'health_data_statistics': {
                'total_records': total_records,
                'records_last_24h': records_last_24h,
                'average_records_per_day': round(total_records / 30) if total_records > 0 else 0
            },
            'alert_statistics': {
                'total_alerts': total_alerts,
                'active_alerts': active_alerts,
                'critical_alerts': critical_alerts,
                'severity_breakdown': [
                    {'severity': severity.value, 'count': count} for severity, count in alert_severity_stats
                ]
            },
            'appointment_statistics': {
                'total_appointments': total_appointments,
                'upcoming_appointments': upcoming_appointments
            },
            'communication_statistics': {
                'total_messages': total_messages,
                'messages_last_24h': messages_last_24h
            },
            'provider_statistics': {
                'verified_providers': verified_providers,
                'pending_verification': pending_verification,
                'verification_rate': round((verified_providers / (verified_providers + pending_verification) * 100) if (verified_providers + pending_verification) > 0 else 0, 2)
            },
            'system_health': {
                'database_status': database_status,
                'storage_usage_percentage': storage_usage,
                'last_updated': datetime.utcnow().isoformat()
            }
        }), 200
        
    except Exception as e:
        logger.error(f"Error fetching admin dashboard: {str(e)}")
        return jsonify({'error': 'Failed to fetch dashboard data'}), 500

@admin_bp.route('/system-settings', methods=['GET'])
@jwt_required()
@admin_required
def get_system_settings():
    """Get system-wide settings"""
    try:
        # These would typically come from a settings table or configuration
        settings = {
            'security': {
                'password_min_length': 8,
                'password_require_special_chars': True,
                'session_timeout_minutes': 120,
                'max_login_attempts': 5,
                'account_lockout_duration_minutes': 30
            },
            'monitoring': {
                'alert_check_interval_minutes': 5,
                'data_retention_days': 2555,  # 7 years for medical data
                'auto_device_sync_enabled': True,
                'real_time_monitoring_enabled': True
            },
            'notifications': {
                'email_notifications_enabled': True,
                'sms_notifications_enabled': True,
                'push_notifications_enabled': True,
                'notification_retry_attempts': 3
            },
            'integrations': {
                'fhir_endpoint_url': current_app.config.get('FHIR_BASE_URL'),
                'fhir_enabled': True,
                'device_api_timeout_seconds': 30,
                'video_call_max_duration_minutes': 60
            },
            'maintenance': {
                'maintenance_mode_enabled': False,
                'scheduled_maintenance_window': '02:00-04:00 UTC',
                'backup_frequency_hours': 24,
                'log_retention_days': 90
            }
        }
        
        return jsonify({'settings': settings}), 200
        
    except Exception as e:
        logger.error(f"Error fetching system settings: {str(e)}")
        return jsonify({'error': 'Failed to fetch system settings'}), 500

@admin_bp.route('/system-settings', methods=['PUT'])
@jwt_required()
@admin_required
def update_system_settings():
    """Update system-wide settings"""
    try:
        data = request.get_json()
        
        # Validate and update settings
        # This would typically update a settings table or configuration file
        # For now, we'll just validate the structure
        
        required_sections = ['security', 'monitoring', 'notifications', 'integrations', 'maintenance']
        for section in required_sections:
            if section not in data:
                return jsonify({'error': f'Missing required section: {section}'}), 400
        
        # Log the settings update
        current_user_id = get_jwt_identity()
        logger.info(f"System settings updated by admin user {current_user_id}")
        
        return jsonify({
            'message': 'System settings updated successfully',
            'updated_at': datetime.utcnow().isoformat()
        }), 200
        
    except Exception as e:
        logger.error(f"Error updating system settings: {str(e)}")
        return jsonify({'error': 'Failed to update system settings'}), 500

@admin_bp.route('/providers/verification', methods=['GET'])
@jwt_required()
@admin_required
def get_pending_provider_verifications():
    """Get list of healthcare providers pending verification"""
    try:
        page = request.args.get('page', 1, type=int)
        per_page = request.args.get('per_page', 20, type=int)
        
        pending_providers = HealthcareProvider.query.filter_by(verified=False).paginate(
            page=page, per_page=per_page, error_out=False
        )
        
        providers_data = []
        for provider in pending_providers.items:
            user = User.query.get(provider.user_id)
            providers_data.append({
                'id': provider.id,
                'user_id': provider.user_id,
                'email': user.email if user else None,
                'first_name': user.first_name if user else None,
                'last_name': user.last_name if user else None,
                'license_number': provider.license_number,
                'provider_type': provider.provider_type.value if provider.provider_type else None,
                'specialization': provider.specialization,
                'organization': provider.organization,
                'phone_number': provider.phone_number,
                'address': provider.address,
                'created_at': provider.created_at.isoformat(),
                'verification_documents': provider.verification_documents
            })
        
        return jsonify({
            'pending_providers': providers_data,
            'pagination': {
                'page': page,
                'per_page': per_page,
                'total': pending_providers.total,
                'pages': pending_providers.pages,
                'has_next': pending_providers.has_next,
                'has_prev': pending_providers.has_prev
            }
        }), 200
        
    except Exception as e:
        logger.error(f"Error fetching pending verifications: {str(e)}")
        return jsonify({'error': 'Failed to fetch pending verifications'}), 500

@admin_bp.route('/providers/<int:provider_id>/verify', methods=['POST'])
@jwt_required()
@admin_required
def verify_healthcare_provider(provider_id):
    """Verify a healthcare provider"""
    try:
        data = request.get_json()
        approved = data.get('approved', False)
        notes = data.get('notes', '')
        
        provider = HealthcareProvider.query.get(provider_id)
        if not provider:
            return jsonify({'error': 'Healthcare provider not found'}), 404
        
        if approved:
            provider.verified = True
            provider.verification_notes = notes
            provider.verified_at = datetime.utcnow()
            provider.verified_by = get_jwt_identity()
            
            try:
                db.session.commit()
                logger.info(f"Healthcare provider {provider_id} verified by admin {get_jwt_identity()}")
                
                # TODO: Send notification to provider about verification approval
                
                return jsonify({
                    'message': 'Healthcare provider verified successfully',
                    'provider_id': provider_id
                }), 200
                
            except IntegrityError:
                db.session.rollback()
                return jsonify({'error': 'Database error during verification'}), 500
        else:
            # Rejection - could mark as rejected or delete
            provider.verification_notes = notes
            provider.verification_rejected = True
            provider.verified_at = datetime.utcnow()
            provider.verified_by = get_jwt_identity()
            
            try:
                db.session.commit()
                logger.info(f"Healthcare provider {provider_id} verification rejected by admin {get_jwt_identity()}")
                
                # TODO: Send notification to provider about verification rejection
                
                return jsonify({
                    'message': 'Healthcare provider verification rejected',
                    'provider_id': provider_id
                }), 200
                
            except IntegrityError:
                db.session.rollback()
                return jsonify({'error': 'Database error during rejection'}), 500
        
    except Exception as e:
        logger.error(f"Error verifying healthcare provider: {str(e)}")
        return jsonify({'error': 'Failed to verify healthcare provider'}), 500

@admin_bp.route('/system-logs', methods=['GET'])
@jwt_required()
@admin_required
def get_system_logs():
    """Get system logs for monitoring and debugging"""
    try:
        page = request.args.get('page', 1, type=int)
        per_page = request.args.get('per_page', 100, type=int)
        level = request.args.get('level', 'INFO')
        start_date = request.args.get('start_date')
        end_date = request.args.get('end_date')
        
        # This would typically read from log files or a logging database
        # For now, return a placeholder response
        logs = [
            {
                'timestamp': datetime.utcnow().isoformat(),
                'level': 'INFO',
                'module': 'admin',
                'message': 'System logs endpoint accessed',
                'user_id': get_jwt_identity()
            }
        ]
        
        return jsonify({
            'logs': logs,
            'pagination': {
                'page': page,
                'per_page': per_page,
                'total': len(logs),
                'pages': 1
            },
            'filters': {
                'level': level,
                'start_date': start_date,
                'end_date': end_date
            }
        }), 200
        
    except Exception as e:
        logger.error(f"Error fetching system logs: {str(e)}")
        return jsonify({'error': 'Failed to fetch system logs'}), 500

@admin_bp.route('/system-backup', methods=['POST'])
@jwt_required()
@admin_required
def create_system_backup():
    """Create a system backup"""
    try:
        data = request.get_json()
        backup_type = data.get('type', 'full')  # full, incremental, database_only
        
        # This would trigger actual backup processes
        # For now, return a placeholder response
        
        backup_id = f"backup_{datetime.utcnow().strftime('%Y%m%d_%H%M%S')}"
        
        logger.info(f"System backup initiated by admin {get_jwt_identity()}: {backup_id}")
        
        return jsonify({
            'message': 'System backup initiated',
            'backup_id': backup_id,
            'backup_type': backup_type,
            'status': 'in_progress',
            'initiated_at': datetime.utcnow().isoformat(),
            'initiated_by': get_jwt_identity()
        }), 202
        
    except Exception as e:
        logger.error(f"Error creating system backup: {str(e)}")
        return jsonify({'error': 'Failed to create system backup'}), 500

@admin_bp.route('/maintenance-mode', methods=['POST'])
@jwt_required()
@admin_required
def toggle_maintenance_mode():
    """Toggle system maintenance mode"""
    try:
        data = request.get_json()
        enabled = data.get('enabled', False)
        message = data.get('message', 'System is under maintenance')
        
        # This would update system configuration
        # For now, just log the action
        
        current_user_id = get_jwt_identity()
        action = "enabled" if enabled else "disabled"
        logger.info(f"Maintenance mode {action} by admin {current_user_id}")
        
        return jsonify({
            'message': f'Maintenance mode {action}',
            'enabled': enabled,
            'maintenance_message': message,
            'updated_by': current_user_id,
            'updated_at': datetime.utcnow().isoformat()
        }), 200
        
    except Exception as e:
        logger.error(f"Error toggling maintenance mode: {str(e)}")
        return jsonify({'error': 'Failed to toggle maintenance mode'}), 500

@admin_bp.route('/data-export', methods=['POST'])
@jwt_required()
@admin_required
def export_system_data():
    """Export system data for backup or migration"""
    try:
        data = request.get_json()
        export_type = data.get('type', 'all')  # all, users, patients, providers, health_data
        format_type = data.get('format', 'json')  # json, csv, xml
        date_range = data.get('date_range', {})
        
        # This would handle actual data export
        # For now, return a placeholder response
        
        export_id = f"export_{datetime.utcnow().strftime('%Y%m%d_%H%M%S')}"
        
        logger.info(f"Data export initiated by admin {get_jwt_identity()}: {export_id}")
        
        return jsonify({
            'message': 'Data export initiated',
            'export_id': export_id,
            'export_type': export_type,
            'format': format_type,
            'status': 'in_progress',
            'initiated_at': datetime.utcnow().isoformat(),
            'initiated_by': get_jwt_identity()
        }), 202
        
    except Exception as e:
        logger.error(f"Error exporting system data: {str(e)}")
        return jsonify({'error': 'Failed to export system data'}), 500

@admin_bp.route('/alerts/overview', methods=['GET'])
@jwt_required()
@admin_required
def get_alerts_overview():
    """Get comprehensive alerts overview for admin monitoring"""
    try:
        # Get alert statistics by severity
        alert_stats = db.session.query(
            Alert.severity,
            func.count(Alert.id).label('total'),
            func.sum(func.cast(Alert.resolved == False, db.Integer)).label('active')
        ).group_by(Alert.severity).all()
        
        # Get recent critical alerts
        recent_critical = Alert.query.filter(
            Alert.severity == AlertSeverity.CRITICAL,
            Alert.created_at >= datetime.utcnow() - timedelta(hours=24)
        ).order_by(Alert.created_at.desc()).limit(10).all()
        
        # Get alert trends (last 7 days)
        seven_days_ago = datetime.utcnow() - timedelta(days=7)
        daily_alerts = db.session.query(
            func.date(Alert.created_at).label('date'),
            func.count(Alert.id).label('count')
        ).filter(Alert.created_at >= seven_days_ago).group_by(
            func.date(Alert.created_at)
        ).all()
        
        alerts_overview = {
            'statistics': [
                {
                    'severity': stat.severity.value,
                    'total': stat.total,
                    'active': stat.active,
                    'resolved': stat.total - stat.active
                }
                for stat in alert_stats
            ],
            'recent_critical': [
                {
                    'id': alert.id,
                    'patient_id': alert.patient_id,
                    'condition': alert.condition,
                    'message': alert.message,
                    'created_at': alert.created_at.isoformat(),
                    'resolved': alert.resolved
                }
                for alert in recent_critical
            ],
            'daily_trends': [
                {
                    'date': str(trend.date),
                    'count': trend.count
                }
                for trend in daily_alerts
            ]
        }
        
        return jsonify(alerts_overview), 200
        
    except Exception as e:
        logger.error(f"Error fetching alerts overview: {str(e)}")
        return jsonify({'error': 'Failed to fetch alerts overview'}), 500
