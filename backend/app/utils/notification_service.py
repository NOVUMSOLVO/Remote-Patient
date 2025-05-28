"""
Notification Service Module
Handles in-app notifications, email notifications, and WebSocket real-time notifications
"""

from datetime import datetime
from flask import current_app
from typing import Dict, List, Optional, Any
import logging
from app.utils.websocket_service import get_websocket_service

logger = logging.getLogger(__name__)

class NotificationService:
    """Service for handling various types of notifications"""
    
    def __init__(self):
        self.websocket_service = get_websocket_service()
    
    def send_message_notification(self, message) -> bool:
        """Send notification for new message"""
        try:
            # Get recipient details
            recipient = message.recipient
            sender = message.sender
            
            # Create notification data
            notification_data = {
                'type': 'new_message',
                'title': 'New Message',
                'message': f'You have a new message from {sender.first_name} {sender.last_name}',
                'data': {
                    'message_id': message.id,
                    'sender': {
                        'id': sender.id,
                        'name': f"{sender.first_name} {sender.last_name}",
                        'role': sender.role.value
                    },
                    'subject': message.subject,
                    'timestamp': message.created_at.isoformat()
                },
                'timestamp': datetime.utcnow().isoformat()
            }
            
            # Send real-time notification via WebSocket
            self._send_realtime_notification(recipient.id, notification_data)
            
            # Send email notification if enabled
            self._send_email_notification(
                recipient.email,
                'New Message - RPM System',
                f'You have received a new message from {sender.first_name} {sender.last_name}. '
                f'Please log in to the RPM system to view your message.'
            )
            
            logger.info(f"Message notification sent to user {recipient.id}")
            return True
            
        except Exception as e:
            logger.error(f"Failed to send message notification: {str(e)}")
            return False
    
    def send_appointment_notification(self, appointment) -> bool:
        """Send notification for new/updated appointment"""
        try:
            # Get patient and provider details
            patient = appointment.patient.user
            provider = appointment.healthcare_provider.user
            
            # Create notifications for both patient and provider
            patient_notification = {
                'type': 'appointment_scheduled',
                'title': 'Appointment Scheduled',
                'message': f'Your appointment with {provider.first_name} {provider.last_name} '
                          f'is scheduled for {appointment.scheduled_time.strftime("%B %d, %Y at %I:%M %p")}',
                'data': {
                    'appointment_id': appointment.id,
                    'appointment_type': appointment.appointment_type,
                    'scheduled_time': appointment.scheduled_time.isoformat(),
                    'provider': {
                        'name': f"{provider.first_name} {provider.last_name}",
                        'specialization': appointment.healthcare_provider.specialization
                    },
                    'video_link': appointment.video_link
                },
                'timestamp': datetime.utcnow().isoformat()
            }
            
            provider_notification = {
                'type': 'appointment_scheduled',
                'title': 'New Appointment',
                'message': f'New appointment scheduled with {patient.first_name} {patient.last_name} '
                          f'for {appointment.scheduled_time.strftime("%B %d, %Y at %I:%M %p")}',
                'data': {
                    'appointment_id': appointment.id,
                    'appointment_type': appointment.appointment_type,
                    'scheduled_time': appointment.scheduled_time.isoformat(),
                    'patient': {
                        'name': f"{patient.first_name} {patient.last_name}",
                        'nhs_number': patient.nhs_number
                    },
                    'video_link': appointment.video_link
                },
                'timestamp': datetime.utcnow().isoformat()
            }
            
            # Send real-time notifications
            self._send_realtime_notification(patient.id, patient_notification)
            self._send_realtime_notification(provider.id, provider_notification)
            
            # Send email notifications
            self._send_email_notification(
                patient.email,
                'Appointment Scheduled - RPM System',
                f'Your appointment with {provider.first_name} {provider.last_name} '
                f'is scheduled for {appointment.scheduled_time.strftime("%B %d, %Y at %I:%M %p")}. '
                f'Please log in to the RPM system for more details.'
            )
            
            self._send_email_notification(
                provider.email,
                'New Appointment - RPM System',
                f'You have a new appointment scheduled with {patient.first_name} {patient.last_name} '
                f'for {appointment.scheduled_time.strftime("%B %d, %Y at %I:%M %p")}. '
                f'Please log in to the RPM system for more details.'
            )
            
            logger.info(f"Appointment notifications sent for appointment {appointment.id}")
            return True
            
        except Exception as e:
            logger.error(f"Failed to send appointment notification: {str(e)}")
            return False
    
    def send_appointment_reminder(self, appointment, minutes_before: int = 15) -> bool:
        """Send appointment reminder notification"""
        try:
            patient = appointment.patient.user
            provider = appointment.healthcare_provider.user
            
            # Create reminder notifications
            patient_reminder = {
                'type': 'appointment_reminder',
                'title': 'Appointment Reminder',
                'message': f'Your appointment with {provider.first_name} {provider.last_name} '
                          f'starts in {minutes_before} minutes',
                'data': {
                    'appointment_id': appointment.id,
                    'appointment_type': appointment.appointment_type,
                    'scheduled_time': appointment.scheduled_time.isoformat(),
                    'video_link': appointment.video_link,
                    'minutes_before': minutes_before
                },
                'timestamp': datetime.utcnow().isoformat(),
                'priority': 'high'
            }
            
            provider_reminder = {
                'type': 'appointment_reminder',
                'title': 'Appointment Reminder',
                'message': f'Your appointment with {patient.first_name} {patient.last_name} '
                          f'starts in {minutes_before} minutes',
                'data': {
                    'appointment_id': appointment.id,
                    'appointment_type': appointment.appointment_type,
                    'scheduled_time': appointment.scheduled_time.isoformat(),
                    'video_link': appointment.video_link,
                    'minutes_before': minutes_before
                },
                'timestamp': datetime.utcnow().isoformat(),
                'priority': 'high'
            }
            
            # Send real-time notifications
            self._send_realtime_notification(patient.id, patient_reminder)
            self._send_realtime_notification(provider.id, provider_reminder)
            
            logger.info(f"Appointment reminders sent for appointment {appointment.id}")
            return True
            
        except Exception as e:
            logger.error(f"Failed to send appointment reminder: {str(e)}")
            return False
    
    def send_video_consultation_notification(self, room_id: str, user_ids: List[int], 
                                           event_type: str, data: Dict[str, Any]) -> bool:
        """Send video consultation related notifications"""
        try:
            notification_messages = {
                'consultation_started': 'Video consultation has started',
                'participant_joined': f'{data.get("participant_name", "A participant")} joined the consultation',
                'participant_left': f'{data.get("participant_name", "A participant")} left the consultation',
                'consultation_ended': 'Video consultation has ended'
            }
            
            notification_data = {
                'type': f'video_consultation_{event_type}',
                'title': 'Video Consultation',
                'message': notification_messages.get(event_type, 'Video consultation update'),
                'data': {
                    'room_id': room_id,
                    'event_type': event_type,
                    **data
                },
                'timestamp': datetime.utcnow().isoformat()
            }
            
            # Send to all specified users
            for user_id in user_ids:
                self._send_realtime_notification(user_id, notification_data)
            
            logger.info(f"Video consultation notification sent: {event_type} for room {room_id}")
            return True
            
        except Exception as e:
            logger.error(f"Failed to send video consultation notification: {str(e)}")
            return False
    
    def send_system_notification(self, user_ids: List[int], title: str, 
                                message: str, notification_type: str = 'system',
                                data: Optional[Dict[str, Any]] = None) -> bool:
        """Send system-wide notifications"""
        try:
            notification_data = {
                'type': notification_type,
                'title': title,
                'message': message,
                'data': data or {},
                'timestamp': datetime.utcnow().isoformat()
            }
            
            # Send to all specified users
            for user_id in user_ids:
                self._send_realtime_notification(user_id, notification_data)
            
            logger.info(f"System notification sent to {len(user_ids)} users")
            return True
            
        except Exception as e:
            logger.error(f"Failed to send system notification: {str(e)}")
            return False
    
    def send_alert_notification(self, alert, user_ids: List[int]) -> bool:
        """Send alert-related notifications"""
        try:
            notification_data = {
                'type': 'patient_alert',
                'title': f'{alert.severity.upper()} Alert',
                'message': f'Patient alert: {alert.title}',
                'data': {
                    'alert_id': alert.id,
                    'patient_id': alert.patient_id,
                    'severity': alert.severity,
                    'title': alert.title,
                    'description': alert.description,
                    'created_at': alert.created_at.isoformat()
                },
                'timestamp': datetime.utcnow().isoformat(),
                'priority': 'high' if alert.severity in ['critical', 'high'] else 'normal'
            }
            
            # Send to specified users (usually healthcare providers)
            for user_id in user_ids:
                self._send_realtime_notification(user_id, notification_data)
            
            logger.info(f"Alert notification sent for alert {alert.id}")
            return True
            
        except Exception as e:
            logger.error(f"Failed to send alert notification: {str(e)}")
            return False
    
    def _send_realtime_notification(self, user_id: int, notification_data: Dict[str, Any]) -> bool:
        """Send real-time notification via WebSocket"""
        try:
            if self.websocket_service:
                self.websocket_service.send_to_user(user_id, 'notification', notification_data)
                return True
            return False
            
        except Exception as e:
            logger.error(f"Failed to send real-time notification: {str(e)}")
            return False
    
    def _send_email_notification(self, email: str, subject: str, body: str) -> bool:
        """Send email notification (placeholder implementation)"""
        try:
            # In production, integrate with email service (SendGrid, AWS SES, etc.)
            # For now, just log the email that would be sent
            logger.info(f"Email notification: TO={email}, SUBJECT={subject}")
            
            # Email sending implementation would go here
            # Example:
            # email_service = EmailService()
            # return email_service.send_email(email, subject, body)
            
            return True
            
        except Exception as e:
            logger.error(f"Failed to send email notification: {str(e)}")
            return False
    
    def get_user_notifications(self, user_id: int, page: int = 1, 
                              per_page: int = 20) -> Dict[str, Any]:
        """Get notifications for a user (placeholder for database implementation)"""
        try:
            # In a full implementation, this would query a notifications table
            # For now, return empty results
            return {
                'notifications': [],
                'pagination': {
                    'page': page,
                    'per_page': per_page,
                    'total': 0,
                    'pages': 0,
                    'has_next': False,
                    'has_prev': False
                }
            }
            
        except Exception as e:
            logger.error(f"Failed to get user notifications: {str(e)}")
            return {
                'notifications': [],
                'pagination': {
                    'page': 1,
                    'per_page': 20,
                    'total': 0,
                    'pages': 0,
                    'has_next': False,
                    'has_prev': False
                }
            }

# Global notification service instance
notification_service = NotificationService()

def get_notification_service() -> NotificationService:
    """Get the global notification service instance"""
    return notification_service
