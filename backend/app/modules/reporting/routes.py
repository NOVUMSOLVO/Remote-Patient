"""
Reporting and Analytics Module for Remote Patient Monitoring
Provides comprehensive reporting, analytics, and insights
"""

from flask import Blueprint, request, jsonify, current_app
from flask_jwt_extended import jwt_required, get_jwt_identity
from sqlalchemy import func, text, and_, or_
from sqlalchemy.exc import IntegrityError
from app.models import (
    db, User, PatientProfile, HealthcareProvider, Device, HealthRecord,
    Alert, Appointment, Message, Report, UserRole, AlertSeverity,
    DeviceType, AppointmentStatus, ReportType
)
from app.modules.rbac.routes import admin_required, healthcare_provider_required
from datetime import datetime, timedelta
import json
import statistics
import logging

reporting_bp = Blueprint('reporting', __name__, url_prefix='/api/reporting')
logger = logging.getLogger(__name__)

@reporting_bp.route('/dashboard/patient/<int:patient_id>', methods=['GET'])
@jwt_required()
def get_patient_dashboard(patient_id):
    """Get comprehensive patient dashboard with health analytics"""
    try:
        current_user_id = get_jwt_identity()
        user = User.query.get(current_user_id)
        
        # Verify access to patient data
        if user.role == UserRole.PATIENT:
            patient = PatientProfile.query.filter_by(user_id=current_user_id).first()
            if not patient or patient.id != patient_id:
                return jsonify({'error': 'Access denied'}), 403
        elif user.role == UserRole.HEALTHCARE_PROVIDER:
            provider = HealthcareProvider.query.filter_by(user_id=current_user_id).first()
            patient = PatientProfile.query.get(patient_id)
            if not provider or not patient or patient.primary_provider_id != provider.id:
                return jsonify({'error': 'Access denied'}), 403
        elif user.role != UserRole.ADMIN:
            return jsonify({'error': 'Access denied'}), 403
        
        patient = PatientProfile.query.get(patient_id)
        if not patient:
            return jsonify({'error': 'Patient not found'}), 404
        
        # Get time range from query parameters
        days = request.args.get('days', 30, type=int)
        start_date = datetime.utcnow() - timedelta(days=days)
        
        # Health records analytics
        health_records = HealthRecord.query.filter(
            HealthRecord.patient_id == patient_id,
            HealthRecord.recorded_at >= start_date
        ).order_by(HealthRecord.recorded_at.desc()).all()
        
        # Vital signs trends
        vital_trends = {}
        vital_types = ['blood_pressure_systolic', 'blood_pressure_diastolic', 'heart_rate', 
                      'blood_glucose', 'weight', 'temperature', 'oxygen_saturation']
        
        for vital in vital_types:
            values = []
            timestamps = []
            for record in health_records:
                if vital in record.data:
                    values.append(record.data[vital])
                    timestamps.append(record.recorded_at.isoformat())
            
            if values:
                vital_trends[vital] = {
                    'values': values,
                    'timestamps': timestamps,
                    'current': values[0] if values else None,
                    'average': round(statistics.mean(values), 2),
                    'min': min(values),
                    'max': max(values),
                    'trend': 'stable'  # This would include trend analysis
                }
        
        # Device usage analytics
        devices = Device.query.filter_by(patient_id=patient_id, is_active=True).all()
        device_analytics = []
        
        for device in devices:
            device_records = [r for r in health_records if r.device_id == device.id]
            last_sync = max([r.recorded_at for r in device_records]) if device_records else None
            
            device_analytics.append({
                'device_id': device.id,
                'device_name': device.device_name,
                'device_type': device.device_type.value,
                'total_readings': len(device_records),
                'last_sync': last_sync.isoformat() if last_sync else None,
                'battery_level': device.battery_level,
                'connection_status': device.connection_status
            })
        
        # Alert analytics
        alerts = Alert.query.filter(
            Alert.patient_id == patient_id,
            Alert.created_at >= start_date
        ).all()
        
        alert_analytics = {
            'total_alerts': len(alerts),
            'active_alerts': len([a for a in alerts if not a.resolved]),
            'critical_alerts': len([a for a in alerts if a.severity == AlertSeverity.CRITICAL]),
            'severity_breakdown': {}
        }
        
        for severity in AlertSeverity:
            count = len([a for a in alerts if a.severity == severity])
            alert_analytics['severity_breakdown'][severity.value] = count
        
        # Appointment analytics
        appointments = Appointment.query.filter(
            Appointment.patient_id == patient_id,
            Appointment.scheduled_time >= start_date
        ).all()
        
        appointment_analytics = {
            'total_appointments': len(appointments),
            'completed': len([a for a in appointments if a.status == AppointmentStatus.COMPLETED]),
            'cancelled': len([a for a in appointments if a.status == AppointmentStatus.CANCELLED]),
            'upcoming': len([a for a in appointments if a.status == AppointmentStatus.SCHEDULED and a.scheduled_time > datetime.utcnow()])
        }
        
        # Health score calculation (simplified)
        health_score = calculate_health_score(vital_trends, alert_analytics, device_analytics)
        
        # Medication adherence (if medication data is available)
        medication_adherence = calculate_medication_adherence(patient_id, days)
        
        dashboard_data = {
            'patient_info': {
                'id': patient.id,
                'name': f"{patient.user.first_name} {patient.user.last_name}",
                'nhs_number': patient.nhs_number,
                'age': calculate_age(patient.date_of_birth) if patient.date_of_birth else None
            },
            'time_period': {
                'days': days,
                'start_date': start_date.isoformat(),
                'end_date': datetime.utcnow().isoformat()
            },
            'health_score': health_score,
            'vital_trends': vital_trends,
            'device_analytics': device_analytics,
            'alert_analytics': alert_analytics,
            'appointment_analytics': appointment_analytics,
            'medication_adherence': medication_adherence,
            'total_readings': len(health_records),
            'last_reading': health_records[0].recorded_at.isoformat() if health_records else None
        }
        
        return jsonify(dashboard_data), 200
        
    except Exception as e:
        logger.error(f"Error generating patient dashboard: {str(e)}")
        return jsonify({'error': 'Failed to generate patient dashboard'}), 500

@reporting_bp.route('/analytics/population', methods=['GET'])
@jwt_required()
@healthcare_provider_required
def get_population_analytics():
    """Get population health analytics for healthcare providers"""
    try:
        current_user_id = get_jwt_identity()
        user = User.query.get(current_user_id)
        
        # Get patients based on user role
        if user.role == UserRole.HEALTHCARE_PROVIDER:
            provider = HealthcareProvider.query.filter_by(user_id=current_user_id).first()
            if not provider:
                return jsonify({'error': 'Provider profile not found'}), 404
            patients = PatientProfile.query.filter_by(primary_provider_id=provider.id).all()
        elif user.role == UserRole.ADMIN:
            patients = PatientProfile.query.all()
        else:
            return jsonify({'error': 'Access denied'}), 403
        
        patient_ids = [p.id for p in patients]
        
        # Get time range
        days = request.args.get('days', 30, type=int)
        start_date = datetime.utcnow() - timedelta(days=days)
        
        # Demographics analytics
        age_groups = {'0-17': 0, '18-30': 0, '31-50': 0, '51-70': 0, '70+': 0}
        gender_distribution = {'male': 0, 'female': 0, 'other': 0}
        
        for patient in patients:
            if patient.date_of_birth:
                age = calculate_age(patient.date_of_birth)
                if age < 18:
                    age_groups['0-17'] += 1
                elif age <= 30:
                    age_groups['18-30'] += 1
                elif age <= 50:
                    age_groups['31-50'] += 1
                elif age <= 70:
                    age_groups['51-70'] += 1
                else:
                    age_groups['70+'] += 1
            
            if patient.gender:
                gender_distribution[patient.gender.lower()] = gender_distribution.get(patient.gender.lower(), 0) + 1
        
        # Health conditions analytics
        conditions_count = {}
        for patient in patients:
            if patient.medical_conditions:
                for condition in patient.medical_conditions:
                    conditions_count[condition] = conditions_count.get(condition, 0) + 1
        
        # Alert trends
        alert_trends = db.session.query(
            func.date(Alert.created_at).label('date'),
            Alert.severity,
            func.count(Alert.id).label('count')
        ).filter(
            Alert.patient_id.in_(patient_ids),
            Alert.created_at >= start_date
        ).group_by(
            func.date(Alert.created_at),
            Alert.severity
        ).all()
        
        # Device usage statistics
        device_usage = db.session.query(
            Device.device_type,
            func.count(Device.id).label('count'),
            func.avg(func.cast(Device.is_active, db.Integer)).label('active_rate')
        ).filter(
            Device.patient_id.in_(patient_ids)
        ).group_by(Device.device_type).all()
        
        # Health metrics averages
        recent_records = HealthRecord.query.filter(
            HealthRecord.patient_id.in_(patient_ids),
            HealthRecord.recorded_at >= start_date
        ).all()
        
        metrics_averages = {}
        vital_types = ['blood_pressure_systolic', 'blood_pressure_diastolic', 'heart_rate', 
                      'blood_glucose', 'weight', 'temperature', 'oxygen_saturation']
        
        for vital in vital_types:
            values = []
            for record in recent_records:
                if vital in record.data and record.data[vital] is not None:
                    values.append(record.data[vital])
            
            if values:
                metrics_averages[vital] = {
                    'average': round(statistics.mean(values), 2),
                    'median': round(statistics.median(values), 2),
                    'std_dev': round(statistics.stdev(values), 2) if len(values) > 1 else 0,
                    'count': len(values)
                }
        
        population_analytics = {
            'patient_count': len(patients),
            'time_period': {
                'days': days,
                'start_date': start_date.isoformat(),
                'end_date': datetime.utcnow().isoformat()
            },
            'demographics': {
                'age_groups': age_groups,
                'gender_distribution': gender_distribution
            },
            'health_conditions': dict(list(conditions_count.items())[:10]),  # Top 10 conditions
            'alert_trends': [
                {
                    'date': str(trend.date),
                    'severity': trend.severity.value,
                    'count': trend.count
                }
                for trend in alert_trends
            ],
            'device_usage': [
                {
                    'device_type': usage.device_type.value,
                    'count': usage.count,
                    'active_rate': round(usage.active_rate * 100, 2)
                }
                for usage in device_usage
            ],
            'health_metrics_averages': metrics_averages,
            'total_health_records': len(recent_records)
        }
        
        return jsonify(population_analytics), 200
        
    except Exception as e:
        logger.error(f"Error generating population analytics: {str(e)}")
        return jsonify({'error': 'Failed to generate population analytics'}), 500

@reporting_bp.route('/reports', methods=['GET'])
@jwt_required()
def get_reports():
    """Get available reports for the current user"""
    try:
        current_user_id = get_jwt_identity()
        user = User.query.get(current_user_id)
        
        page = request.args.get('page', 1, type=int)
        per_page = request.args.get('per_page', 20, type=int)
        report_type = request.args.get('type')
        
        query = Report.query
        
        # Filter based on user role
        if user.role == UserRole.PATIENT:
            patient = PatientProfile.query.filter_by(user_id=current_user_id).first()
            if patient:
                query = query.filter_by(patient_id=patient.id)
            else:
                return jsonify({'reports': [], 'pagination': {}}), 200
        elif user.role == UserRole.HEALTHCARE_PROVIDER:
            provider = HealthcareProvider.query.filter_by(user_id=current_user_id).first()
            if provider:
                query = query.filter_by(generated_by=current_user_id)
            else:
                return jsonify({'reports': [], 'pagination': {}}), 200
        # Admin can see all reports
        
        # Apply type filter
        if report_type:
            try:
                type_enum = ReportType(report_type)
                query = query.filter_by(report_type=type_enum)
            except ValueError:
                return jsonify({'error': 'Invalid report type'}), 400
        
        # Apply pagination
        reports_pagination = query.order_by(Report.created_at.desc()).paginate(
            page=page, per_page=per_page, error_out=False
        )
        
        reports_data = []
        for report in reports_pagination.items:
            reports_data.append({
                'id': report.id,
                'title': report.title,
                'report_type': report.report_type.value,
                'description': report.description,
                'patient_id': report.patient_id,
                'generated_by': report.generated_by,
                'created_at': report.created_at.isoformat(),
                'period_start': report.period_start.isoformat() if report.period_start else None,
                'period_end': report.period_end.isoformat() if report.period_end else None,
                'file_path': report.file_path,
                'parameters': report.parameters
            })
        
        return jsonify({
            'reports': reports_data,
            'pagination': {
                'page': page,
                'per_page': per_page,
                'total': reports_pagination.total,
                'pages': reports_pagination.pages,
                'has_next': reports_pagination.has_next,
                'has_prev': reports_pagination.has_prev
            }
        }), 200
        
    except Exception as e:
        logger.error(f"Error fetching reports: {str(e)}")
        return jsonify({'error': 'Failed to fetch reports'}), 500

@reporting_bp.route('/reports/generate', methods=['POST'])
@jwt_required()
def generate_report():
    """Generate a new report"""
    try:
        data = request.get_json()
        
        required_fields = ['title', 'report_type', 'patient_id']
        for field in required_fields:
            if field not in data:
                return jsonify({'error': f'Missing required field: {field}'}), 400
        
        current_user_id = get_jwt_identity()
        user = User.query.get(current_user_id)
        
        # Validate report type
        try:
            report_type = ReportType(data['report_type'])
        except ValueError:
            return jsonify({'error': 'Invalid report type'}), 400
        
        # Verify access to patient
        patient_id = data['patient_id']
        if user.role == UserRole.PATIENT:
            patient = PatientProfile.query.filter_by(user_id=current_user_id).first()
            if not patient or patient.id != patient_id:
                return jsonify({'error': 'Access denied'}), 403
        elif user.role == UserRole.HEALTHCARE_PROVIDER:
            provider = HealthcareProvider.query.filter_by(user_id=current_user_id).first()
            patient = PatientProfile.query.get(patient_id)
            if not provider or not patient or patient.primary_provider_id != provider.id:
                return jsonify({'error': 'Access denied'}), 403
        elif user.role != UserRole.ADMIN:
            return jsonify({'error': 'Access denied'}), 403
        
        # Create report record
        report = Report(
            title=data['title'],
            report_type=report_type,
            description=data.get('description', ''),
            patient_id=patient_id,
            generated_by=current_user_id,
            period_start=datetime.fromisoformat(data['period_start']) if data.get('period_start') else None,
            period_end=datetime.fromisoformat(data['period_end']) if data.get('period_end') else None,
            parameters=data.get('parameters', {})
        )
        
        db.session.add(report)
        db.session.commit()
        
        # Generate actual report content based on type
        report_content = generate_report_content(report)
        
        # Save report file (this would typically save to file system or cloud storage)
        report.file_path = f"reports/{report.id}_{report.report_type.value}.json"
        report.content = report_content
        
        db.session.commit()
        
        logger.info(f"Report generated: {report.id} by user {current_user_id}")
        
        return jsonify({
            'message': 'Report generated successfully',
            'report_id': report.id,
            'title': report.title,
            'report_type': report.report_type.value,
            'created_at': report.created_at.isoformat(),
            'file_path': report.file_path
        }), 201
        
    except Exception as e:
        logger.error(f"Error generating report: {str(e)}")
        return jsonify({'error': 'Failed to generate report'}), 500

@reporting_bp.route('/reports/<int:report_id>', methods=['GET'])
@jwt_required()
def get_report_details(report_id):
    """Get detailed report content"""
    try:
        current_user_id = get_jwt_identity()
        user = User.query.get(current_user_id)
        
        report = Report.query.get(report_id)
        if not report:
            return jsonify({'error': 'Report not found'}), 404
        
        # Verify access to report
        if user.role == UserRole.PATIENT:
            patient = PatientProfile.query.filter_by(user_id=current_user_id).first()
            if not patient or patient.id != report.patient_id:
                return jsonify({'error': 'Access denied'}), 403
        elif user.role == UserRole.HEALTHCARE_PROVIDER:
            if report.generated_by != current_user_id:
                provider = HealthcareProvider.query.filter_by(user_id=current_user_id).first()
                patient = PatientProfile.query.get(report.patient_id)
                if not provider or not patient or patient.primary_provider_id != provider.id:
                    return jsonify({'error': 'Access denied'}), 403
        elif user.role != UserRole.ADMIN:
            return jsonify({'error': 'Access denied'}), 403
        
        report_data = {
            'id': report.id,
            'title': report.title,
            'report_type': report.report_type.value,
            'description': report.description,
            'patient_id': report.patient_id,
            'generated_by': report.generated_by,
            'created_at': report.created_at.isoformat(),
            'period_start': report.period_start.isoformat() if report.period_start else None,
            'period_end': report.period_end.isoformat() if report.period_end else None,
            'parameters': report.parameters,
            'content': report.content
        }
        
        return jsonify(report_data), 200
        
    except Exception as e:
        logger.error(f"Error fetching report details: {str(e)}")
        return jsonify({'error': 'Failed to fetch report details'}), 500

@reporting_bp.route('/export/<format_type>', methods=['POST'])
@jwt_required()
def export_data(format_type):
    """Export data in various formats (CSV, PDF, Excel)"""
    try:
        data = request.get_json()
        export_type = data.get('type', 'patient_data')
        patient_id = data.get('patient_id')
        date_range = data.get('date_range', {})
        
        current_user_id = get_jwt_identity()
        user = User.query.get(current_user_id)
        
        if format_type not in ['csv', 'pdf', 'excel']:
            return jsonify({'error': 'Unsupported export format'}), 400
        
        # Verify access
        if patient_id:
            if user.role == UserRole.PATIENT:
                patient = PatientProfile.query.filter_by(user_id=current_user_id).first()
                if not patient or patient.id != patient_id:
                    return jsonify({'error': 'Access denied'}), 403
            elif user.role == UserRole.HEALTHCARE_PROVIDER:
                provider = HealthcareProvider.query.filter_by(user_id=current_user_id).first()
                patient = PatientProfile.query.get(patient_id)
                if not provider or not patient or patient.primary_provider_id != provider.id:
                    return jsonify({'error': 'Access denied'}), 403
            elif user.role != UserRole.ADMIN:
                return jsonify({'error': 'Access denied'}), 403
        
        # Generate export file (this would create actual files)
        export_id = f"export_{datetime.utcnow().strftime('%Y%m%d_%H%M%S')}"
        file_name = f"{export_id}.{format_type}"
        
        logger.info(f"Data export initiated: {export_id} by user {current_user_id}")
        
        return jsonify({
            'message': 'Export initiated',
            'export_id': export_id,
            'format': format_type,
            'file_name': file_name,
            'status': 'processing',
            'download_url': f"/api/reporting/download/{export_id}"
        }), 202
        
    except Exception as e:
        logger.error(f"Error exporting data: {str(e)}")
        return jsonify({'error': 'Failed to export data'}), 500

# Helper functions
def calculate_age(birth_date):
    """Calculate age from birth date"""
    if not birth_date:
        return None
    today = datetime.utcnow().date()
    return today.year - birth_date.year - ((today.month, today.day) < (birth_date.month, birth_date.day))

def calculate_health_score(vital_trends, alert_analytics, device_analytics):
    """Calculate a simplified health score"""
    score = 100
    
    # Deduct points for active alerts
    if alert_analytics['active_alerts'] > 0:
        score -= alert_analytics['active_alerts'] * 5
    
    # Deduct points for critical alerts
    if alert_analytics['critical_alerts'] > 0:
        score -= alert_analytics['critical_alerts'] * 10
    
    # Deduct points for inactive devices
    inactive_devices = len([d for d in device_analytics if not d.get('last_sync')])
    score -= inactive_devices * 5
    
    # Ensure score doesn't go below 0
    return max(0, min(100, score))

def calculate_medication_adherence(patient_id, days):
    """Calculate medication adherence (simplified)"""
    # This would integrate with medication tracking if available
    return {
        'adherence_rate': 85.5,
        'missed_doses': 3,
        'total_doses': 21,
        'last_updated': datetime.utcnow().isoformat()
    }

def generate_report_content(report):
    """Generate report content based on report type"""
    if report.report_type == ReportType.HEALTH_SUMMARY:
        return generate_health_summary_report(report)
    elif report.report_type == ReportType.MEDICATION_ADHERENCE:
        return generate_medication_adherence_report(report)
    elif report.report_type == ReportType.VITAL_TRENDS:
        return generate_vital_trends_report(report)
    elif report.report_type == ReportType.ALERT_HISTORY:
        return generate_alert_history_report(report)
    else:
        return {'error': 'Unknown report type'}

def generate_health_summary_report(report):
    """Generate health summary report content"""
    # This would contain actual report generation logic
    return {
        'summary': 'Health summary report',
        'patient_id': report.patient_id,
        'period': {
            'start': report.period_start.isoformat() if report.period_start else None,
            'end': report.period_end.isoformat() if report.period_end else None
        },
        'generated_at': datetime.utcnow().isoformat()
    }

def generate_medication_adherence_report(report):
    """Generate medication adherence report content"""
    return {
        'summary': 'Medication adherence report',
        'patient_id': report.patient_id,
        'adherence_data': calculate_medication_adherence(report.patient_id, 30),
        'generated_at': datetime.utcnow().isoformat()
    }

def generate_vital_trends_report(report):
    """Generate vital trends report content"""
    return {
        'summary': 'Vital trends report',
        'patient_id': report.patient_id,
        'trends': 'Detailed vital signs analysis would go here',
        'generated_at': datetime.utcnow().isoformat()
    }

def generate_alert_history_report(report):
    """Generate alert history report content"""
    return {
        'summary': 'Alert history report',
        'patient_id': report.patient_id,
        'alert_summary': 'Detailed alert analysis would go here',
        'generated_at': datetime.utcnow().isoformat()
    }
