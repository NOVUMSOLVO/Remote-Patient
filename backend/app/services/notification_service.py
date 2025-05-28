"""
Notification service for alerts and messages to healthcare providers.
"""
from flask import current_app
from flask_mail import Message
from flask_socketio import emit
from app import mail, socketio


def send_email_notification(recipient, subject, body):
    """
    Send an email notification.
    
    Args:
        recipient (str): Email address of the recipient
        subject (str): Email subject
        body (str): Email body content
    """
    try:
        msg = Message(
            subject=subject,
            recipients=[recipient],
            body=body
        )
        mail.send(msg)
        return True
    except Exception as e:
        current_app.logger.error(f"Failed to send email: {str(e)}")
        return False


def send_realtime_alert(user_id, alert_type, message, data=None):
    """
    Send a real-time alert via WebSocket.
    
    Args:
        user_id (int): ID of the user to receive the alert
        alert_type (str): Type of alert (e.g., 'critical', 'warning', 'info')
        message (str): Alert message content
        data (dict, optional): Additional data to include with the alert
    """
    payload = {
        'alert_type': alert_type,
        'message': message,
    }
    
    if data:
        payload['data'] = data
        
    # Emit to the specific user's room
    emit('alert', payload, room=f'user_{user_id}', namespace='/alerts')
    
    return True


def check_metrics_threshold(metric_value, metric_type):
    """
    Check if a metric exceeds predefined thresholds.
    
    Args:
        metric_value (float): The value of the metric to check
        metric_type (str): The type of metric (e.g., 'heart_rate')
        
    Returns:
        tuple: (exceeded, alert_type, message)
            - exceeded (bool): Whether the threshold was exceeded
            - alert_type (str): 'critical', 'warning', or None
            - message (str): Alert message or None
    """
    # Example threshold checks
    thresholds = {
        'heart_rate': {
            'critical_high': 140,
            'warning_high': 120,
            'warning_low': 50,
            'critical_low': 40
        },
        'blood_pressure_systolic': {
            'critical_high': 180,
            'warning_high': 140,
            'warning_low': 90,
            'critical_low': 70
        },
        'temperature': {
            'critical_high': 39.5,
            'warning_high': 38.5,
            'warning_low': 35.0,
            'critical_low': 34.0
        }
    }
    
    if metric_type not in thresholds:
        return False, None, None
        
    t = thresholds[metric_type]
    
    if metric_value >= t.get('critical_high', float('inf')):
        return True, 'critical', f"{metric_type} critically high: {metric_value}"
    elif metric_value <= t.get('critical_low', float('-inf')):
        return True, 'critical', f"{metric_type} critically low: {metric_value}"
    elif metric_value >= t.get('warning_high', float('inf')):
        return True, 'warning', f"{metric_type} high: {metric_value}"
    elif metric_value <= t.get('warning_low', float('-inf')):
        return True, 'warning', f"{metric_type} low: {metric_value}"
        
    return False, None, None