"""
Monitoring service for patient data processing.
"""
from datetime import datetime, timedelta
from app.models.patient import Patient, PatientMetric
from app.services.notification_service import (
    check_metrics_threshold, 
    send_realtime_alert, 
    send_email_notification
)
from app import db


def record_patient_metric(patient_id, metric_type, value, unit):
    """
    Record a new patient metric and check if it exceeds thresholds.
    
    Args:
        patient_id (int): The patient's ID
        metric_type (str): Type of metric (e.g., 'heart_rate')
        value (float): The value of the metric
        unit (str): The unit of measurement
        
    Returns:
        tuple: (metric, alert_sent)
            - metric: The created PatientMetric object
            - alert_sent (bool): Whether an alert was sent
    """
    # Record the metric
    metric = PatientMetric(
        patient_id=patient_id,
        metric_type=metric_type,
        value=value,
        unit=unit
    )
    db.session.add(metric)
    db.session.commit()
    
    # Check if the metric exceeds thresholds
    exceeded, alert_type, message = check_metrics_threshold(value, metric_type)
    
    if exceeded:
        # Get the patient's provider IDs (simplified example)
        # In a real application, you would query provider-patient relationships
        patient = Patient.query.get(patient_id)
        
        # Assuming a patient's healthcare providers have IDs stored somewhere
        # For now, just using a placeholder
        provider_ids = get_patient_providers(patient_id)
        
        # Alert each provider
        alert_sent = False
        for provider_id in provider_ids:
            # Send real-time alert via WebSocket
            alert_data = {
                'patient_id': patient_id,
                'patient_name': f"{patient.first_name} {patient.last_name}",
                'metric_type': metric_type,
                'value': value,
                'unit': unit,
                'timestamp': datetime.now().isoformat()
            }
            
            send_realtime_alert(
                user_id=provider_id,
                alert_type=alert_type,
                message=message,
                data=alert_data
            )
            
            # For critical alerts, also send email
            if alert_type == 'critical':
                # In a real app, get the provider's email from the database
                provider_email = get_provider_email(provider_id)
                if provider_email:
                    send_email_notification(
                        recipient=provider_email,
                        subject=f"CRITICAL ALERT: Patient {patient.first_name} {patient.last_name}",
                        body=f"Critical alert for patient {patient.first_name} {patient.last_name}:\n\n"
                             f"{message}\n\n"
                             f"Value: {value} {unit}\n"
                             f"Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}"
                    )
            
            alert_sent = True
        
        return metric, alert_sent
    
    return metric, False


def get_patient_metrics(patient_id, metric_type=None, start_time=None, end_time=None):
    """
    Get patient metrics within a time range.
    
    Args:
        patient_id (int): The patient's ID
        metric_type (str, optional): Type of metric to filter by
        start_time (datetime, optional): Start time for the query
        end_time (datetime, optional): End time for the query
        
    Returns:
        list: List of PatientMetric objects
    """
    query = PatientMetric.query.filter_by(patient_id=patient_id)
    
    if metric_type:
        query = query.filter_by(metric_type=metric_type)
    
    if start_time:
        query = query.filter(PatientMetric.timestamp >= start_time)
    
    if end_time:
        query = query.filter(PatientMetric.timestamp <= end_time)
    
    return query.order_by(PatientMetric.timestamp.desc()).all()


# Placeholder functions - in a real app these would query the database
def get_patient_providers(patient_id):
    """
    Get the healthcare provider IDs for a patient.
    
    Args:
        patient_id (int): The patient's ID
        
    Returns:
        list: List of provider IDs
    """
    # In a real application, this would query a patient-provider relationship table
    # For example: return db.session.query(PatientProvider.provider_id).filter_by(patient_id=patient_id).all()
    
    # For this template, just return a placeholder
    return [1, 2]  # Example provider IDs


def get_provider_email(provider_id):
    """
    Get a provider's email address.
    
    Args:
        provider_id (int): The provider's ID
        
    Returns:
        str: The provider's email address
    """
    # In a real application, this would query the user table
    # For example: return User.query.get(provider_id).email
    
    # For this template, just return a placeholder
    return "provider@example.com"