"""
Communication Module
In-app secure, encrypted messaging with doctors, video appointment support
"""

from flask import Blueprint, request, jsonify, current_app
from flask_jwt_extended import jwt_required, get_jwt_identity
from datetime import datetime, timedelta
from sqlalchemy import and_, desc, or_

from app import db
from app.models import Message, Appointment, User, PatientProfile, HealthcareProvider
from app.utils.encryption import encrypt_message, decrypt_message
from app.utils.video_service import VideoService, get_video_service
from app.utils.notification_service import NotificationService, get_notification_service
from app.utils.websocket_service import get_websocket_service

communication_bp = Blueprint('communication', __name__)

@communication_bp.route('/messages', methods=['GET'])
@jwt_required()
def get_messages():
    """Get messages for the current user"""
    try:
        user_id = get_jwt_identity()
        user = User.query.get(user_id)
        
        if not user:
            return jsonify({'error': 'User not found'}), 404
        
        # Get query parameters
        page = int(request.args.get('page', 1))
        per_page = min(int(request.args.get('per_page', 20)), 100)
        conversation_with = request.args.get('conversation_with')
        
        # Build query for messages where user is sender or recipient
        query = Message.query.filter(
            or_(
                Message.sender_id == user_id,
                Message.recipient_id == user_id
            )
        )
        
        # Filter by conversation partner
        if conversation_with:
            try:
                other_user_id = int(conversation_with)
                query = query.filter(
                    or_(
                        and_(Message.sender_id == user_id, Message.recipient_id == other_user_id),
                        and_(Message.sender_id == other_user_id, Message.recipient_id == user_id)
                    )
                )
            except ValueError:
                return jsonify({'error': 'Invalid conversation_with parameter'}), 400
        
        # Order by creation date (newest first)
        query = query.order_by(desc(Message.created_at))
        
        # Paginate
        paginated_messages = query.paginate(
            page=page,
            per_page=per_page,
            error_out=False
        )
        
        # Format messages
        messages = []
        for message in paginated_messages.items:
            # Decrypt message content if encrypted
            content = message.content
            if message.is_encrypted:
                try:
                    content = decrypt_message(message.content)
                except Exception as e:
                    current_app.logger.error(f'Failed to decrypt message: {str(e)}')
                    content = '[Message could not be decrypted]'
            
            message_data = {
                'id': message.id,
                'subject': message.subject,
                'content': content,
                'is_read': message.is_read,
                'created_at': message.created_at.isoformat(),
                'read_at': message.read_at.isoformat() if message.read_at else None,
                'sender': {
                    'id': message.sender.id,
                    'name': f"{message.sender.first_name} {message.sender.last_name}",
                    'role': message.sender.role.value
                },
                'recipient': {
                    'id': message.recipient.id,
                    'name': f"{message.recipient.first_name} {message.recipient.last_name}",
                    'role': message.recipient.role.value
                }
            }
            
            messages.append(message_data)
        
        return jsonify({
            'messages': messages,
            'pagination': {
                'page': page,
                'per_page': per_page,
                'total': paginated_messages.total,
                'pages': paginated_messages.pages,
                'has_next': paginated_messages.has_next,
                'has_prev': paginated_messages.has_prev
            }
        }), 200
        
    except Exception as e:
        current_app.logger.error(f'Get messages error: {str(e)}')
        return jsonify({'error': 'Failed to retrieve messages'}), 500

@communication_bp.route('/messages', methods=['POST'])
@jwt_required()
def send_message():
    """Send a secure message"""
    try:
        user_id = get_jwt_identity()
        user = User.query.get(user_id)
        
        if not user:
            return jsonify({'error': 'User not found'}), 404
        
        data = request.get_json()
        
        # Validate required fields
        required_fields = ['recipient_id', 'content']
        for field in required_fields:
            if not data.get(field):
                return jsonify({'error': f'{field} is required'}), 400
        
        # Validate recipient
        recipient = User.query.get(data['recipient_id'])
        if not recipient:
            return jsonify({'error': 'Recipient not found'}), 404
        
        # Check if user can message this recipient
        if not can_message_user(user, recipient):
            return jsonify({'error': 'You cannot send messages to this user'}), 403
        
        # Encrypt message content
        content = data['content']
        is_encrypted = True
        try:
            encrypted_content = encrypt_message(content)
        except Exception as e:
            current_app.logger.error(f'Encryption failed: {str(e)}')
            encrypted_content = content
            is_encrypted = False
        
        # Create message
        message = Message(
            sender_id=user_id,
            recipient_id=data['recipient_id'],
            subject=data.get('subject', '').strip() or None,
            content=encrypted_content,
            is_encrypted=is_encrypted
        )
        
        db.session.add(message)
        db.session.commit()
        
        # Send notification to recipient
        notification_service = get_notification_service()
        websocket_service = get_websocket_service()
        try:
            notification_service.send_message_notification(message)
            
            # Send real-time message update via WebSocket
            message_data = {
                'id': message.id,
                'subject': message.subject,
                'content': content,  # Use decrypted content for real-time
                'created_at': message.created_at.isoformat(),
                'sender': {
                    'id': user.id,
                    'name': f"{user.first_name} {user.last_name}",
                    'role': user.role.value
                }
            }
            
            # Send to recipient's conversation room
            websocket_service.send_to_user(data['recipient_id'], 'new_message', message_data)
            
        except Exception as e:
            current_app.logger.error(f'Failed to send message notification: {str(e)}')
        
        return jsonify({
            'message': 'Message sent successfully',
            'message_id': message.id
        }, 201)
        
    except Exception as e:
        db.session.rollback()
        current_app.logger.error(f'Send message error: {str(e)}')
        return jsonify({'error': 'Failed to send message'}), 500

@communication_bp.route('/messages/<int:message_id>/read', methods=['POST'])
@jwt_required()
def mark_message_read(message_id):
    """Mark message as read"""
    try:
        user_id = get_jwt_identity()
        
        message = Message.query.filter_by(id=message_id, recipient_id=user_id).first()
        if not message:
            return jsonify({'error': 'Message not found'}), 404
        
        if not message.is_read:
            message.is_read = True
            message.read_at = datetime.utcnow()
            db.session.commit()
            
            # Send real-time update via WebSocket
            websocket_service = get_websocket_service()
            try:
                websocket_service.send_to_user(message.sender_id, 'message_read', {
                    'message_id': message.id,
                    'read_at': message.read_at.isoformat(),
                    'reader_id': user_id
                })
            except Exception as e:
                current_app.logger.error(f'Failed to send read notification: {str(e)}')
        
        return jsonify({'message': 'Message marked as read'}), 200
        
    except Exception as e:
        db.session.rollback()
        current_app.logger.error(f'Mark message read error: {str(e)}')
        return jsonify({'error': 'Failed to mark message as read'}), 500

@communication_bp.route('/conversations', methods=['GET'])
@jwt_required()
def get_conversations():
    """Get list of conversations"""
    try:
        user_id = get_jwt_identity()
        user = User.query.get(user_id)
        
        if not user:
            return jsonify({'error': 'User not found'}), 404
        
        # Get unique conversation partners
        conversations = db.session.query(
            Message.sender_id,
            Message.recipient_id
        ).filter(
            or_(
                Message.sender_id == user_id,
                Message.recipient_id == user_id
            )
        ).distinct().all()
        
        # Extract unique user IDs
        conversation_partners = set()
        for conv in conversations:
            if conv.sender_id != user_id:
                conversation_partners.add(conv.sender_id)
            if conv.recipient_id != user_id:
                conversation_partners.add(conv.recipient_id)
        
        # Get conversation details
        conversation_list = []
        for partner_id in conversation_partners:
            partner = User.query.get(partner_id)
            if not partner:
                continue
            
            # Get latest message in conversation
            latest_message = Message.query.filter(
                or_(
                    and_(Message.sender_id == user_id, Message.recipient_id == partner_id),
                    and_(Message.sender_id == partner_id, Message.recipient_id == user_id)
                )
            ).order_by(desc(Message.created_at)).first()
            
            # Count unread messages from this partner
            unread_count = Message.query.filter_by(
                sender_id=partner_id,
                recipient_id=user_id,
                is_read=False
            ).count()
            
            conversation_data = {
                'partner': {
                    'id': partner.id,
                    'name': f"{partner.first_name} {partner.last_name}",
                    'role': partner.role.value
                },
                'latest_message': {
                    'id': latest_message.id,
                    'subject': latest_message.subject,
                    'created_at': latest_message.created_at.isoformat(),
                    'is_from_me': latest_message.sender_id == user_id
                } if latest_message else None,
                'unread_count': unread_count
            }
            
            conversation_list.append(conversation_data)
        
        # Sort by latest message date
        conversation_list.sort(
            key=lambda x: x['latest_message']['created_at'] if x['latest_message'] else '',
            reverse=True
        )
        
        return jsonify({'conversations': conversation_list}), 200
        
    except Exception as e:
        current_app.logger.error(f'Get conversations error: {str(e)}')
        return jsonify({'error': 'Failed to retrieve conversations'}), 500

@communication_bp.route('/appointments', methods=['GET'])
@jwt_required()
def get_appointments():
    """Get appointments for the current user"""
    try:
        user_id = get_jwt_identity()
        user = User.query.get(user_id)
        
        if not user:
            return jsonify({'error': 'User not found'}), 404
        
        # Get query parameters
        page = int(request.args.get('page', 1))
        per_page = min(int(request.args.get('per_page', 20)), 100)
        status = request.args.get('status')
        
        # Build query based on user role
        if user.role.value == 'patient':
            if not user.patient_profile:
                return jsonify({'error': 'Patient profile not found'}), 404
            query = Appointment.query.filter_by(patient_id=user.patient_profile.id)
        else:
            if not user.healthcare_provider:
                return jsonify({'error': 'Healthcare provider profile not found'}), 404
            query = Appointment.query.filter_by(provider_id=user.healthcare_provider.id)
        
        # Apply status filter
        if status:
            query = query.filter_by(status=status)
        
        # Order by scheduled time
        query = query.order_by(Appointment.scheduled_time)
        
        # Paginate
        paginated_appointments = query.paginate(
            page=page,
            per_page=per_page,
            error_out=False
        )
        
        # Format appointments
        appointments = []
        for appointment in paginated_appointments.items:
            appointment_data = {
                'id': appointment.id,
                'appointment_type': appointment.appointment_type,
                'scheduled_time': appointment.scheduled_time.isoformat(),
                'duration': appointment.duration,
                'status': appointment.status,
                'notes': appointment.notes,
                'video_link': appointment.video_link,
                'created_at': appointment.created_at.isoformat()
            }
            
            # Add patient or provider info based on user role
            if user.role.value == 'patient':
                provider = appointment.healthcare_provider.user
                appointment_data['provider'] = {
                    'id': provider.id,
                    'name': f"{provider.first_name} {provider.last_name}",
                    'specialization': appointment.healthcare_provider.specialization
                }
            else:
                patient = appointment.patient.user
                appointment_data['patient'] = {
                    'id': patient.id,
                    'name': f"{patient.first_name} {patient.last_name}",
                    'nhs_number': patient.nhs_number
                }
            
            appointments.append(appointment_data)
        
        return jsonify({
            'appointments': appointments,
            'pagination': {
                'page': page,
                'per_page': per_page,
                'total': paginated_appointments.total,
                'pages': paginated_appointments.pages,
                'has_next': paginated_appointments.has_next,
                'has_prev': paginated_appointments.has_prev
            }
        }), 200
        
    except Exception as e:
        current_app.logger.error(f'Get appointments error: {str(e)}')
        return jsonify({'error': 'Failed to retrieve appointments'}), 500

@communication_bp.route('/appointments', methods=['POST'])
@jwt_required()
def schedule_appointment():
    """Schedule a new appointment"""
    try:
        user_id = get_jwt_identity()
        user = User.query.get(user_id)
        
        if not user:
            return jsonify({'error': 'User not found'}), 404
        
        data = request.get_json()
        
        # Validate required fields
        required_fields = ['scheduled_time', 'appointment_type']
        for field in required_fields:
            if not data.get(field):
                return jsonify({'error': f'{field} is required'}), 400
        
        # Parse scheduled time
        try:
            scheduled_time = datetime.fromisoformat(data['scheduled_time'])
        except ValueError:
            return jsonify({'error': 'Invalid scheduled_time format. Use ISO format.'}), 400
        
        # Check if scheduled time is in the future
        if scheduled_time <= datetime.utcnow():
            return jsonify({'error': 'Scheduled time must be in the future'}), 400
        
        # Determine patient and provider based on user role
        if user.role.value == 'patient':
            if not user.patient_profile:
                return jsonify({'error': 'Patient profile not found'}), 404
            
            patient_id = user.patient_profile.id
            provider_id = data.get('provider_id')
            
            if not provider_id:
                return jsonify({'error': 'provider_id is required for patients'}), 400
            
            provider = HealthcareProvider.query.get(provider_id)
            if not provider:
                return jsonify({'error': 'Healthcare provider not found'}), 404
        else:
            if not user.healthcare_provider:
                return jsonify({'error': 'Healthcare provider profile not found'}), 404
            
            provider_id = user.healthcare_provider.id
            patient_id = data.get('patient_id')
            
            if not patient_id:
                return jsonify({'error': 'patient_id is required for providers'}), 400
            
            patient = PatientProfile.query.get(patient_id)
            if not patient:
                return jsonify({'error': 'Patient not found'}), 404
        
        # Create appointment
        appointment = Appointment(
            patient_id=patient_id,
            provider_id=provider_id,
            appointment_type=data['appointment_type'],
            scheduled_time=scheduled_time,
            duration=data.get('duration', 30),
            notes=data.get('notes', '').strip() or None
        )
        
        # Generate video link for video appointments
        if data['appointment_type'] == 'video':
            video_service = get_video_service()
            try:
                video_link = video_service.create_meeting_room(appointment)
                appointment.video_link = video_link
            except Exception as e:
                current_app.logger.error(f'Failed to create video link: {str(e)}')
        
        db.session.add(appointment)
        db.session.commit()
        
        # Send notifications to both parties
        notification_service = get_notification_service()
        websocket_service = get_websocket_service()
        try:
            notification_service.send_appointment_notification(appointment)
            
            # Send real-time appointment updates
            appointment_data = {
                'id': appointment.id,
                'appointment_type': appointment.appointment_type,
                'scheduled_time': appointment.scheduled_time.isoformat(),
                'duration': appointment.duration,
                'status': appointment.status,
                'video_link': appointment.video_link
            }
            
            # Send to both patient and provider
            patient_user_id = appointment.patient.user.id
            provider_user_id = appointment.healthcare_provider.user.id
            
            websocket_service.send_to_user(patient_user_id, 'appointment_scheduled', appointment_data)
            websocket_service.send_to_user(provider_user_id, 'appointment_scheduled', appointment_data)
            
        except Exception as e:
            current_app.logger.error(f'Failed to send appointment notification: {str(e)}')
        
        return jsonify({
            'message': 'Appointment scheduled successfully',
            'appointment_id': appointment.id,
            'video_link': appointment.video_link
        }), 201
        
    except Exception as e:
        db.session.rollback()
        current_app.logger.error(f'Schedule appointment error: {str(e)}')
        return jsonify({'error': 'Failed to schedule appointment'}), 500

# Video Consultation Endpoints

@communication_bp.route('/video/rooms/<room_id>/join', methods=['POST'])
@jwt_required()
def join_video_room(room_id):
    """Join a video consultation room"""
    try:
        user_id = get_jwt_identity()
        user = User.query.get(user_id)
        
        if not user:
            return jsonify({'error': 'User not found'}), 404
        
        data = request.get_json() or {}
        appointment_id = data.get('appointment_id')
        
        # Validate appointment access
        if appointment_id:
            if user.role.value == 'patient':
                appointment = Appointment.query.filter_by(
                    id=appointment_id,
                    patient_id=user.patient_profile.id if user.patient_profile else None
                ).first()
            else:
                appointment = Appointment.query.filter_by(
                    id=appointment_id,
                    provider_id=user.healthcare_provider.id if user.healthcare_provider else None
                ).first()
            
            if not appointment:
                return jsonify({'error': 'Appointment not found or access denied'}), 403
        
        # Join video room
        video_service = get_video_service()
        try:
            room_info = video_service.join_room(room_id, user_id, user.role.value)
            
            # Send notification to other participants
            notification_service = get_notification_service()
            websocket_service = get_websocket_service()
            
            # Get other participants
            other_participants = [p['user_id'] for p in room_info['participants'] if p['user_id'] != user_id]
            
            if other_participants:
                notification_service.send_video_consultation_notification(
                    room_id, 
                    other_participants,
                    'participant_joined',
                    {
                        'participant_name': f"{user.first_name} {user.last_name}",
                        'participant_role': user.role.value
                    }
                )
                
                # Send real-time update to room
                websocket_service.send_to_room(f"video_room_{room_id}", 'participant_joined', {
                    'user_id': user_id,
                    'name': f"{user.first_name} {user.last_name}",
                    'role': user.role.value,
                    'peer_id': room_info['peer_id']
                })
            
            return jsonify(room_info), 200
            
        except ValueError as e:
            return jsonify({'error': str(e)}), 400
        except Exception as e:
            current_app.logger.error(f'Join video room error: {str(e)}')
            return jsonify({'error': 'Failed to join video room'}), 500
        
    except Exception as e:
        current_app.logger.error(f'Join video room error: {str(e)}')
        return jsonify({'error': 'Failed to join video room'}), 500

@communication_bp.route('/video/rooms/<room_id>/leave', methods=['POST'])
@jwt_required()
def leave_video_room(room_id):
    """Leave a video consultation room"""
    try:
        user_id = get_jwt_identity()
        user = User.query.get(user_id)
        
        if not user:
            return jsonify({'error': 'User not found'}), 404
        
        video_service = get_video_service()
        success = video_service.leave_room(room_id, user_id)
        
        if success:
            # Send notification to other participants
            notification_service = get_notification_service()
            websocket_service = get_websocket_service()
            
            # Get room info to find other participants
            room_info = video_service.get_room_info(room_id)
            if room_info and room_info['participants']:
                other_participants = [p['user_id'] for p in room_info['participants'] if p['user_id'] != user_id]
                
                if other_participants:
                    notification_service.send_video_consultation_notification(
                        room_id,
                        other_participants,
                        'participant_left',
                        {
                            'participant_name': f"{user.first_name} {user.last_name}",
                            'participant_role': user.role.value
                        }
                    )
                    
                    # Send real-time update to room
                    websocket_service.send_to_room(f"video_room_{room_id}", 'participant_left', {
                        'user_id': user_id,
                        'name': f"{user.first_name} {user.last_name}",
                        'role': user.role.value
                    })
            
            return jsonify({'message': 'Left video room successfully'}), 200
        else:
            return jsonify({'error': 'Failed to leave video room'}), 400
        
    except Exception as e:
        current_app.logger.error(f'Leave video room error: {str(e)}')
        return jsonify({'error': 'Failed to leave video room'}), 500

@communication_bp.route('/video/rooms/<room_id>/end', methods=['POST'])
@jwt_required()
def end_video_consultation(room_id):
    """End a video consultation (healthcare providers only)"""
    try:
        user_id = get_jwt_identity()
        user = User.query.get(user_id)
        
        if not user:
            return jsonify({'error': 'User not found'}), 404
        
        # Only healthcare providers can end consultations
        if user.role.value not in ['doctor', 'nurse']:
            return jsonify({'error': 'Only healthcare providers can end consultations'}), 403
        
        video_service = get_video_service()
        
        # Get room info before ending
        room_info = video_service.get_room_info(room_id)
        if not room_info:
            return jsonify({'error': 'Video room not found'}), 404
        
        participants = room_info['participants']
        participant_ids = [p['user_id'] for p in participants]
        
        # End the consultation
        success = video_service.end_consultation(room_id, user_id)
        
        if success:
            # Send notifications to all participants
            notification_service = get_notification_service()
            websocket_service = get_websocket_service()
            
            notification_service.send_video_consultation_notification(
                room_id,
                participant_ids,
                'consultation_ended',
                {
                    'ended_by': f"{user.first_name} {user.last_name}",
                    'ended_at': datetime.utcnow().isoformat()
                }
            )
            
            # Send real-time update to room
            websocket_service.send_to_room(f"video_room_{room_id}", 'consultation_ended', {
                'ended_by': user_id,
                'ended_at': datetime.utcnow().isoformat()
            })
            
            return jsonify({'message': 'Video consultation ended successfully'}), 200
        else:
            return jsonify({'error': 'Failed to end video consultation'}), 400
        
    except Exception as e:
        current_app.logger.error(f'End video consultation error: {str(e)}')
        return jsonify({'error': 'Failed to end video consultation'}), 500

@communication_bp.route('/video/rooms/<room_id>/info', methods=['GET'])
@jwt_required()
def get_video_room_info(room_id):
    """Get video room information"""
    try:
        user_id = get_jwt_identity()
        user = User.query.get(user_id)
        
        if not user:
            return jsonify({'error': 'User not found'}), 404
        
        video_service = get_video_service()
        room_info = video_service.get_room_info(room_id)
        
        if not room_info:
            return jsonify({'error': 'Video room not found'}), 404
        
        # Check if user has access to this room
        # In production, add proper access control validation
        
        return jsonify(room_info), 200
        
    except Exception as e:
        current_app.logger.error(f'Get video room info error: {str(e)}')
        return jsonify({'error': 'Failed to get video room information'}), 500

@communication_bp.route('/video/active-consultations', methods=['GET'])
@jwt_required()
def get_active_consultations():
    """Get active video consultations for the current user"""
    try:
        user_id = get_jwt_identity()
        user = User.query.get(user_id)
        
        if not user:
            return jsonify({'error': 'User not found'}), 404
        
        video_service = get_video_service()
        active_consultations = video_service.get_active_consultations(user_id)
        
        return jsonify({
            'active_consultations': active_consultations,
            'count': len(active_consultations)
        }), 200
        
    except Exception as e:
        current_app.logger.error(f'Get active consultations error: {str(e)}')
        return jsonify({'error': 'Failed to get active consultations'}), 500

# Real-time Messaging Endpoints

@communication_bp.route('/messages/typing', methods=['POST'])
@jwt_required()
def send_typing_indicator():
    """Send typing indicator to conversation partner"""
    try:
        user_id = get_jwt_identity()
        user = User.query.get(user_id)
        
        if not user:
            return jsonify({'error': 'User not found'}), 404
        
        data = request.get_json()
        recipient_id = data.get('recipient_id')
        is_typing = data.get('is_typing', True)
        
        if not recipient_id:
            return jsonify({'error': 'recipient_id is required'}), 400
        
        # Send typing indicator via WebSocket
        websocket_service = get_websocket_service()
        websocket_service.send_to_user(recipient_id, 'typing_indicator', {
            'sender_id': user_id,
            'sender_name': f"{user.first_name} {user.last_name}",
            'is_typing': is_typing,
            'timestamp': datetime.utcnow().isoformat()
        })
        
        return jsonify({'message': 'Typing indicator sent'}), 200
        
    except Exception as e:
        current_app.logger.error(f'Send typing indicator error: {str(e)}')
        return jsonify({'error': 'Failed to send typing indicator'}), 500

@communication_bp.route('/messages/online-status', methods=['GET'])
@jwt_required()
def get_online_status():
    """Get online status of conversation partners"""
    try:
        user_id = get_jwt_identity()
        user = User.query.get(user_id)
        
        if not user:
            return jsonify({'error': 'User not found'}), 404
        
        # Get conversation partners
        conversations = db.session.query(
            Message.sender_id,
            Message.recipient_id
        ).filter(
            or_(
                Message.sender_id == user_id,
                Message.recipient_id == user_id
            )
        ).distinct().all()
        
        # Extract unique user IDs
        conversation_partners = set()
        for conv in conversations:
            if conv.sender_id != user_id:
                conversation_partners.add(conv.sender_id)
            if conv.recipient_id != user_id:
                conversation_partners.add(conv.recipient_id)
        
        # Get online status from WebSocket service
        websocket_service = get_websocket_service()
        online_status = {}
        
        for partner_id in conversation_partners:
            online_status[partner_id] = websocket_service.is_user_online(partner_id)
        
        return jsonify({'online_status': online_status}), 200
        
    except Exception as e:
        current_app.logger.error(f'Get online status error: {str(e)}')
        return jsonify({'error': 'Failed to get online status'}), 500

def can_message_user(sender, recipient):
    """Check if sender can message recipient"""
    # Patients can message their healthcare providers
    # Healthcare providers can message their patients
    # Admins can message anyone
    
    if sender.role.value == 'admin':
        return True
    
    if sender.role.value == 'patient' and recipient.role.value in ['doctor', 'nurse']:
        return True
    
    if sender.role.value in ['doctor', 'nurse'] and recipient.role.value == 'patient':
        return True
    
    # Same role users can message each other (e.g., doctor to doctor)
    if sender.role.value == recipient.role.value:
        return True
    
    return False
