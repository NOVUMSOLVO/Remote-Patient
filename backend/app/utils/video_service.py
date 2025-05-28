"""
Video Service Module
Handles video consultation functionality with WebRTC integration
"""

import uuid
import jwt
import time
from datetime import datetime, timedelta
from flask import current_app
from typing import Dict, Optional, Any
import requests
import logging

logger = logging.getLogger(__name__)

class VideoService:
    """Video consultation service with WebRTC support"""
    
    def __init__(self):
        self.room_sessions = {}  # In-memory storage for room sessions
        
    def create_meeting_room(self, appointment) -> str:
        """Create a video meeting room for an appointment"""
        try:
            # Generate unique room ID
            room_id = f"rpm_{appointment.id}_{uuid.uuid4().hex[:8]}"
            
            # Create room session
            room_session = {
                'room_id': room_id,
                'appointment_id': appointment.id,
                'created_at': datetime.utcnow(),
                'participants': [],
                'is_active': True,
                'meeting_url': f"/video-consultation/{room_id}"
            }
            
            # Store room session
            self.room_sessions[room_id] = room_session
            
            # Generate secure meeting URL
            meeting_url = self._generate_meeting_url(room_id, appointment)
            
            logger.info(f"Created video meeting room: {room_id} for appointment: {appointment.id}")
            return meeting_url
            
        except Exception as e:
            logger.error(f"Failed to create meeting room: {str(e)}")
            raise
    
    def _generate_meeting_url(self, room_id: str, appointment) -> str:
        """Generate secure meeting URL with JWT token"""
        try:
            # Create JWT token for room access
            payload = {
                'room_id': room_id,
                'appointment_id': appointment.id,
                'patient_id': appointment.patient_id,
                'provider_id': appointment.provider_id,
                'iat': int(time.time()),
                'exp': int(time.time()) + (2 * 60 * 60)  # 2 hours expiry
            }
            
            token = jwt.encode(
                payload, 
                current_app.config.get('SECRET_KEY', 'dev-secret'),
                algorithm='HS256'
            )
            
            # Return meeting URL with token
            base_url = current_app.config.get('FRONTEND_URL', 'http://localhost:3000')
            return f"{base_url}/video-consultation/{room_id}?token={token}"
            
        except Exception as e:
            logger.error(f"Failed to generate meeting URL: {str(e)}")
            return f"/video-consultation/{room_id}"
    
    def join_room(self, room_id: str, user_id: int, user_role: str) -> Dict[str, Any]:
        """Join a video consultation room"""
        try:
            if room_id not in self.room_sessions:
                raise ValueError("Room not found")
            
            room = self.room_sessions[room_id]
            
            # Check if room is active
            if not room['is_active']:
                raise ValueError("Room is no longer active")
            
            # Add participant
            participant = {
                'user_id': user_id,
                'user_role': user_role,
                'joined_at': datetime.utcnow(),
                'peer_id': f"{user_id}_{uuid.uuid4().hex[:6]}"
            }
            
            # Remove existing participant if rejoining
            room['participants'] = [p for p in room['participants'] if p['user_id'] != user_id]
            room['participants'].append(participant)
            
            # Generate WebRTC configuration
            webrtc_config = self._get_webrtc_config()
            
            return {
                'room_id': room_id,
                'peer_id': participant['peer_id'],
                'participants': [
                    {
                        'user_id': p['user_id'],
                        'user_role': p['user_role'],
                        'peer_id': p['peer_id']
                    } for p in room['participants']
                ],
                'webrtc_config': webrtc_config
            }
            
        except Exception as e:
            logger.error(f"Failed to join room {room_id}: {str(e)}")
            raise
    
    def leave_room(self, room_id: str, user_id: int) -> bool:
        """Leave a video consultation room"""
        try:
            if room_id not in self.room_sessions:
                return False
            
            room = self.room_sessions[room_id]
            
            # Remove participant
            room['participants'] = [p for p in room['participants'] if p['user_id'] != user_id]
            
            # Close room if no participants
            if not room['participants']:
                room['is_active'] = False
                room['ended_at'] = datetime.utcnow()
            
            logger.info(f"User {user_id} left room {room_id}")
            return True
            
        except Exception as e:
            logger.error(f"Failed to leave room {room_id}: {str(e)}")
            return False
    
    def end_consultation(self, room_id: str, user_id: int) -> bool:
        """End a video consultation"""
        try:
            if room_id not in self.room_sessions:
                return False
            
            room = self.room_sessions[room_id]
            
            # Only healthcare providers can end consultations
            appointment_id = room['appointment_id']
            # Additional validation would check if user_id is the provider
            
            room['is_active'] = False
            room['ended_at'] = datetime.utcnow()
            room['ended_by'] = user_id
            
            logger.info(f"Consultation {room_id} ended by user {user_id}")
            return True
            
        except Exception as e:
            logger.error(f"Failed to end consultation {room_id}: {str(e)}")
            return False
    
    def get_room_info(self, room_id: str) -> Optional[Dict[str, Any]]:
        """Get room information"""
        try:
            if room_id not in self.room_sessions:
                return None
            
            room = self.room_sessions[room_id]
            return {
                'room_id': room_id,
                'appointment_id': room['appointment_id'],
                'is_active': room['is_active'],
                'participant_count': len(room['participants']),
                'created_at': room['created_at'].isoformat(),
                'participants': [
                    {
                        'user_id': p['user_id'],
                        'user_role': p['user_role'],
                        'joined_at': p['joined_at'].isoformat()
                    } for p in room['participants']
                ]
            }
            
        except Exception as e:
            logger.error(f"Failed to get room info {room_id}: {str(e)}")
            return None
    
    def _get_webrtc_config(self) -> Dict[str, Any]:
        """Get WebRTC configuration"""
        # In production, you would use TURN/STUN servers
        return {
            'iceServers': [
                {'urls': 'stun:stun.l.google.com:19302'},
                {'urls': 'stun:stun1.l.google.com:19302'},
                # Add TURN servers for production
                # {
                #     'urls': 'turn:your-turn-server.com:3478',
                #     'username': 'username',
                #     'credential': 'password'
                # }
            ],
            'iceCandidatePoolSize': 10
        }
    
    def validate_room_access(self, room_id: str, user_id: int, appointment_id: int) -> bool:
        """Validate if user can access the video room"""
        try:
            if room_id not in self.room_sessions:
                return False
            
            room = self.room_sessions[room_id]
            
            # Check if appointment matches
            if room['appointment_id'] != appointment_id:
                return False
            
            # Additional validation would check if user is part of the appointment
            # This would require database lookup to verify patient/provider relationship
            
            return True
            
        except Exception as e:
            logger.error(f"Failed to validate room access: {str(e)}")
            return False
    
    def get_active_consultations(self, user_id: int) -> list:
        """Get active consultations for a user"""
        try:
            active_consultations = []
            
            for room_id, room in self.room_sessions.items():
                if room['is_active']:
                    # Check if user is a participant
                    user_participant = next(
                        (p for p in room['participants'] if p['user_id'] == user_id),
                        None
                    )
                    
                    if user_participant:
                        active_consultations.append({
                            'room_id': room_id,
                            'appointment_id': room['appointment_id'],
                            'joined_at': user_participant['joined_at'].isoformat(),
                            'participant_count': len(room['participants'])
                        })
            
            return active_consultations
            
        except Exception as e:
            logger.error(f"Failed to get active consultations: {str(e)}")
            return []
    
    def cleanup_expired_rooms(self):
        """Clean up expired room sessions"""
        try:
            current_time = datetime.utcnow()
            expired_rooms = []
            
            for room_id, room in self.room_sessions.items():
                # Clean up rooms older than 24 hours
                if (current_time - room['created_at']).total_seconds() > 86400:
                    expired_rooms.append(room_id)
                    continue
                
                # Clean up inactive rooms with no participants for 1 hour
                if (not room['participants'] and 
                    (current_time - room['created_at']).total_seconds() > 3600):
                    expired_rooms.append(room_id)
            
            for room_id in expired_rooms:
                del self.room_sessions[room_id]
                logger.info(f"Cleaned up expired room: {room_id}")
            
            return len(expired_rooms)
            
        except Exception as e:
            logger.error(f"Failed to cleanup expired rooms: {str(e)}")
            return 0

# Global video service instance
video_service = VideoService()

def get_video_service() -> VideoService:
    """Get the global video service instance"""
    return video_service
