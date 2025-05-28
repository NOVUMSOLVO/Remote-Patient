"""
WebSocket Service for Real-time Communication
Handles real-time alerts, notifications, and device data streaming
"""

from flask import request
from flask_socketio import SocketIO, emit, join_room, leave_room, disconnect
from flask_jwt_extended import decode_token, get_jwt_identity
from datetime import datetime
import logging

logger = logging.getLogger(__name__)

class WebSocketService:
    def __init__(self, app=None, socketio=None):
        self.socketio = socketio
        self.connected_users = {}
        self.room_members = {}
        
        if app is not None:
            self.init_app(app)
    
    def init_app(self, app):
        """Initialize WebSocket service with Flask app"""
        if self.socketio is None:
            self.socketio = SocketIO(
                app,
                cors_allowed_origins="*",
                async_mode='threading',
                logger=True,
                engineio_logger=True
            )
        
        self.register_handlers()
    
    def register_handlers(self):
        """Register WebSocket event handlers"""
        
        @self.socketio.on('connect')
        def handle_connect(auth):
            """Handle client connection"""
            try:
                # Verify JWT token
                if auth and 'token' in auth:
                    token = auth['token']
                    try:
                        # Decode token to get user info
                        decoded_token = decode_token(token)
                        user_id = decoded_token['sub']
                        
                        # Store user connection info
                        self.connected_users[request.sid] = {
                            'user_id': user_id,
                            'connected_at': datetime.utcnow(),
                            'rooms': []
                        }
                        
                        # Join user-specific room for private notifications
                        join_room(f"user_{user_id}")
                        self.connected_users[request.sid]['rooms'].append(f"user_{user_id}")
                        
                        logger.info(f"User {user_id} connected with session {request.sid}")
                        emit('connection_status', {'status': 'connected', 'user_id': user_id})
                        
                    except Exception as e:
                        logger.error(f"Token verification failed: {e}")
                        disconnect()
                        return False
                else:
                    logger.warning("Connection attempt without valid token")
                    disconnect()
                    return False
                    
            except Exception as e:
                logger.error(f"Connection error: {e}")
                disconnect()
                return False
        
        @self.socketio.on('disconnect')
        def handle_disconnect():
            """Handle client disconnection"""
            try:
                if request.sid in self.connected_users:
                    user_info = self.connected_users[request.sid]
                    user_id = user_info['user_id']
                    
                    # Leave all rooms
                    for room in user_info['rooms']:
                        leave_room(room)
                    
                    # Remove from connected users
                    del self.connected_users[request.sid]
                    
                    logger.info(f"User {user_id} disconnected")
                    
            except Exception as e:
                logger.error(f"Disconnection error: {e}")
        
        @self.socketio.on('join_alert_room')
        def handle_join_alert_room(data):
            """Join alert monitoring room"""
            try:
                if request.sid in self.connected_users:
                    room = data.get('room', 'alerts_general')
                    join_room(room)
                    self.connected_users[request.sid]['rooms'].append(room)
                    emit('joined_room', {'room': room, 'status': 'success'})
                    logger.info(f"User joined room: {room}")
                else:
                    emit('error', {'message': 'Not authenticated'})
            except Exception as e:
                logger.error(f"Join room error: {e}")
                emit('error', {'message': 'Failed to join room'})
        
        @self.socketio.on('leave_alert_room')
        def handle_leave_alert_room(data):
            """Leave alert monitoring room"""
            try:
                if request.sid in self.connected_users:
                    room = data.get('room', 'alerts_general')
                    leave_room(room)
                    if room in self.connected_users[request.sid]['rooms']:
                        self.connected_users[request.sid]['rooms'].remove(room)
                    emit('left_room', {'room': room, 'status': 'success'})
                    logger.info(f"User left room: {room}")
                else:
                    emit('error', {'message': 'Not authenticated'})
            except Exception as e:
                logger.error(f"Leave room error: {e}")
                emit('error', {'message': 'Failed to leave room'})
        
        @self.socketio.on('acknowledge_alert')
        def handle_acknowledge_alert(data):
            """Handle alert acknowledgment"""
            try:
                if request.sid in self.connected_users:
                    alert_id = data.get('alert_id')
                    user_id = self.connected_users[request.sid]['user_id']
                    
                    # Broadcast acknowledgment to all connected users
                    self.socketio.emit('alert_acknowledged', {
                        'alert_id': alert_id,
                        'acknowledged_by': user_id,
                        'timestamp': datetime.utcnow().isoformat()
                    }, room='alerts_general')
                    
                    logger.info(f"Alert {alert_id} acknowledged by user {user_id}")
                else:
                    emit('error', {'message': 'Not authenticated'})
            except Exception as e:
                logger.error(f"Acknowledge alert error: {e}")
                emit('error', {'message': 'Failed to acknowledge alert'})
    
    def broadcast_alert(self, alert_data, room='alerts_general'):
        """Broadcast new alert to all connected clients"""
        try:
            self.socketio.emit('new_alert', {
                'alert': alert_data,
                'timestamp': datetime.utcnow().isoformat()
            }, room=room)
            logger.info(f"Alert broadcasted to room: {room}")
        except Exception as e:
            logger.error(f"Broadcast alert error: {e}")
    
    def broadcast_alert_update(self, event_type, alert_data, room='alerts_general'):
        """Broadcast alert updates (acknowledged, resolved, etc.)"""
        try:
            self.socketio.emit(event_type, {
                'alert': alert_data,
                'timestamp': datetime.utcnow().isoformat()
            }, room=room)
            logger.info(f"Alert update '{event_type}' broadcasted to room: {room}")
        except Exception as e:
            logger.error(f"Broadcast alert update error: {e}")
    
    def send_user_notification(self, user_id, notification_data):
        """Send notification to specific user"""
        try:
            self.socketio.emit('notification', {
                'notification': notification_data,
                'timestamp': datetime.utcnow().isoformat()
            }, room=f"user_{user_id}")
            logger.info(f"Notification sent to user: {user_id}")
        except Exception as e:
            logger.error(f"Send notification error: {e}")
    
    def broadcast_device_data(self, device_id, data, room='device_monitoring'):
        """Broadcast real-time device data"""
        try:
            self.socketio.emit('device_data', {
                'device_id': device_id,
                'data': data,
                'timestamp': datetime.utcnow().isoformat()
            }, room=room)
            logger.info(f"Device data broadcasted for device: {device_id}")
        except Exception as e:
            logger.error(f"Broadcast device data error: {e}")
    
    def send_to_user(self, user_id, event_type, data):
        """Send event to specific user"""
        try:
            self.socketio.emit(event_type, {
                'data': data,
                'timestamp': datetime.utcnow().isoformat()
            }, room=f"user_{user_id}")
            logger.info(f"Event '{event_type}' sent to user: {user_id}")
        except Exception as e:
            logger.error(f"Send to user error: {e}")
    
    def send_to_room(self, room_name, event_type, data):
        """Send event to specific room"""
        try:
            self.socketio.emit(event_type, {
                'data': data,
                'timestamp': datetime.utcnow().isoformat()
            }, room=room_name)
            logger.info(f"Event '{event_type}' sent to room: {room_name}")
        except Exception as e:
            logger.error(f"Send to room error: {e}")
    
    def is_user_online(self, user_id):
        """Check if a user is currently online"""
        return self.is_user_connected(user_id)
    
    def send_message(self, event_type, data, room=None):
        """Send message to room or broadcast"""
        try:
            if room:
                self.socketio.emit(event_type, data, room=room)
            else:
                self.socketio.emit(event_type, data)
            logger.info(f"Message '{event_type}' sent to {'room ' + room if room else 'all'}")
        except Exception as e:
            logger.error(f"Send message error: {e}")

    def get_connected_users_count(self):
        """Get count of connected users"""
        return len(self.connected_users)
    
    def get_user_rooms(self, user_id):
        """Get rooms that a user is connected to"""
        user_rooms = []
        for sid, user_info in self.connected_users.items():
            if user_info['user_id'] == user_id:
                user_rooms.extend(user_info['rooms'])
        return user_rooms
    
    def is_user_connected(self, user_id):
        """Check if a user is currently connected"""
        for user_info in self.connected_users.values():
            if user_id == user_info['user_id']:
                return True
        return False

# Global instance
websocket_service = WebSocketService()

def get_websocket_service():
    """Get the global WebSocket service instance"""
    return websocket_service