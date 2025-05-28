import React, { useState, useEffect, useRef } from 'react';
import { useParams, useNavigate, useLocation } from 'react-router-dom';
import { useWebSocket } from '../../hooks/useWebSocket';
import Peer from 'simple-peer';
import toast from 'react-hot-toast';
import axios from 'axios';

// Material UI Icons
import MicIcon from '@material-ui/icons/Mic';
import MicOffIcon from '@material-ui/icons/MicOff';
import VideocamIcon from '@material-ui/icons/Videocam';
import VideocamOffIcon from '@material-ui/icons/VideocamOff';
import CallEndIcon from '@material-ui/icons/CallEnd';
import ScreenShareIcon from '@material-ui/icons/ScreenShare';
import StopScreenShareIcon from '@material-ui/icons/StopScreenShare';
import ChatIcon from '@material-ui/icons/Chat';

const VideoConsultation = () => {
  const { roomId } = useParams();
  const location = useLocation();
  const navigate = useNavigate();
  const token = new URLSearchParams(location.search).get('token') || '';
  
  // WebSocket connection
  const {
    sendMessage,
    lastMessage,
    isConnected,
    connectionError
  } = useWebSocket();
  
  // References and State
  const [peers, setPeers] = useState({});
  const [stream, setStream] = useState(null);
  const [screenShare, setScreenShare] = useState(null);
  const [isAudioEnabled, setIsAudioEnabled] = useState(true);
  const [isVideoEnabled, setIsVideoEnabled] = useState(true);
  const [isScreenSharing, setIsScreenSharing] = useState(false);
  const [isChatOpen, setIsChatOpen] = useState(false);
  const [participants, setParticipants] = useState([]);
  const [roomInfo, setRoomInfo] = useState(null);
  const [isJoining, setIsJoining] = useState(true);
  const [joinError, setJoinError] = useState(null);
  
  // WebRTC configuration
  const [webRtcConfig, setWebRtcConfig] = useState({
    iceServers: [
      { urls: 'stun:stun.l.google.com:19302' },
      { urls: 'stun:stun1.l.google.com:19302' },
    ]
  });
  
  // Local references
  const localVideoRef = useRef(null);
  const peersRef = useRef({});
  const streamRef = useRef(null);
  const isCallActive = useRef(true);
  const userInfoRef = useRef(null);
  
  // Join room on component mount
  useEffect(() => {
    // Get user media
    const setupMediaAndJoinRoom = async () => {
      try {
        // Get user media (camera and microphone)
        const stream = await navigator.mediaDevices.getUserMedia({
          audio: true,
          video: true
        });
        
        // Set local stream
        setStream(stream);
        streamRef.current = stream;
        
        // Display local video
        if (localVideoRef.current) {
          localVideoRef.current.srcObject = stream;
        }
        
        // Join room through API
        await joinRoom();
        
      } catch (error) {
        console.error('Error accessing media devices:', error);
        setJoinError('Failed to access camera or microphone. Please check permissions.');
        toast.error('Failed to access camera or microphone');
      }
    };
    
    setupMediaAndJoinRoom();
    
    // Cleanup when component unmounts
    return () => {
      leaveRoom();
      if (streamRef.current) {
        streamRef.current.getTracks().forEach(track => track.stop());
      }
      if (screenShare) {
        screenShare.getTracks().forEach(track => track.stop());
      }
    };
  }, [roomId]);
  
  // Handle WebSocket messages
  useEffect(() => {
    if (!lastMessage) return;
    
    try {
      const { event, data } = lastMessage;
      
      switch (event) {
        case 'participant_joined':
          handleParticipantJoined(data.data);
          break;
          
        case 'participant_left':
          handleParticipantLeft(data.data);
          break;
          
        case 'consultation_ended':
          handleConsultationEnded(data.data);
          break;
          
        case 'signal':
          handleSignal(data.data);
          break;
          
        default:
          break;
      }
    } catch (error) {
      console.error('Error handling WebSocket message:', error);
    }
  }, [lastMessage]);
  
  // Join the room through API
  const joinRoom = async () => {
    try {
      setIsJoining(true);
      
      // Parse appointment ID from token
      let appointmentId = null;
      try {
        const tokenPayload = JSON.parse(atob(token.split('.')[1]));
        appointmentId = tokenPayload.appointment_id;
      } catch (e) {
        console.error('Error parsing token:', e);
      }
      
      // Join room via API
      const response = await axios.post(`/api/communication/video/rooms/${roomId}/join`, {
        appointment_id: appointmentId
      });
      
      const roomData = response.data;
      setRoomInfo(roomData);
      setWebRtcConfig(roomData.webrtc_config);
      
      // Set user info (for reference)
      userInfoRef.current = {
        peerId: roomData.peer_id
      };
      
      // Join WebSocket room
      sendMessage('join_room', { room: `video_room_${roomId}` });
      
      // Setup peer connections with other participants
      roomData.participants.forEach(participant => {
        if (participant.peer_id !== roomData.peer_id) {
          createPeer(participant.peer_id, participant.user_id);
        }
      });
      
      setParticipants(roomData.participants);
      setIsJoining(false);
      toast.success('Joined video consultation');
      
    } catch (error) {
      console.error('Error joining room:', error);
      setJoinError(`Failed to join room: ${error.response?.data?.error || error.message}`);
      setIsJoining(false);
      toast.error('Failed to join video consultation');
    }
  };
  
  // Leave the room
  const leaveRoom = async () => {
    if (!isCallActive.current) return;
    
    try {
      // Notify server
      await axios.post(`/api/communication/video/rooms/${roomId}/leave`);
      
      // Close all peer connections
      Object.values(peersRef.current).forEach(peer => {
        if (peer.peer) {
          peer.peer.destroy();
        }
      });
      
      // Leave WebSocket room
      sendMessage('leave_room', { room: `video_room_${roomId}` });
      
      // Stop local stream
      if (streamRef.current) {
        streamRef.current.getTracks().forEach(track => track.stop());
      }
      
      // Stop screen sharing if active
      if (screenShare) {
        screenShare.getTracks().forEach(track => track.stop());
      }
      
      isCallActive.current = false;
      toast.success('Left video consultation');
      
    } catch (error) {
      console.error('Error leaving room:', error);
      toast.error('Error leaving consultation');
    }
  };
  
  // End the consultation (healthcare providers only)
  const endConsultation = async () => {
    try {
      await axios.post(`/api/communication/video/rooms/${roomId}/end`);
      leaveRoom();
      navigate('/appointments');
    } catch (error) {
      console.error('Error ending consultation:', error);
      toast.error('Failed to end consultation');
    }
  };
  
  // Create a peer connection to another participant
  const createPeer = (peerId, userId) => {
    if (!streamRef.current) return;
    
    try {
      // Create new peer (initiator)
      const peer = new Peer({
        initiator: true,
        trickle: false,
        stream: streamRef.current,
        config: webRtcConfig
      });
      
      // Handle signals
      peer.on('signal', signal => {
        sendMessage('signal', {
          room: `video_room_${roomId}`,
          peerId: peerId,
          signal,
          from: userInfoRef.current?.peerId
        });
      });
      
      // Handle stream
      peer.on('stream', stream => {
        // Add remote video stream to UI
        setPeers(peers => ({
          ...peers,
          [peerId]: stream
        }));
      });
      
      // Handle close
      peer.on('close', () => {
        removeVideoStream(peerId);
      });
      
      // Handle errors
      peer.on('error', err => {
        console.error('Peer error:', err);
        removeVideoStream(peerId);
      });
      
      // Store peer reference
      peersRef.current[peerId] = { peer, userId };
      
    } catch (error) {
      console.error('Error creating peer:', error);
    }
  };
  
  // Handle a participant joining
  const handleParticipantJoined = (participant) => {
    if (!participant) return;
    
    const { user_id, peer_id } = participant;
    
    // Avoid duplicate connections
    if (peersRef.current[peer_id]) return;
    
    toast.success(`${participant.name} joined the consultation`);
    
    setParticipants(participants => [
      ...participants,
      participant
    ]);
    
    // Create peer connection
    createPeer(peer_id, user_id);
  };
  
  // Handle a participant leaving
  const handleParticipantLeft = (participant) => {
    if (!participant) return;
    
    toast.info(`${participant.name} left the consultation`);
    
    // Remove from participants list
    setParticipants(participants => 
      participants.filter(p => p.user_id !== participant.user_id)
    );
    
    // Find and close the peer connection
    Object.entries(peersRef.current).forEach(([peerId, data]) => {
      if (data.userId === participant.user_id) {
        if (data.peer) {
          data.peer.destroy();
        }
        delete peersRef.current[peerId];
        removeVideoStream(peerId);
      }
    });
  };
  
  // Handle consultation ended by provider
  const handleConsultationEnded = (data) => {
    toast.info('The consultation has ended');
    leaveRoom();
    navigate('/appointments');
  };
  
  // Handle incoming WebRTC signal
  const handleSignal = (data) => {
    if (!data || !data.from || !data.signal) return;
    
    const { from, signal } = data;
    
    // If peer doesn't exist, create it
    if (!peersRef.current[from]) {
      // Create new peer (not initiator)
      const peer = new Peer({
        initiator: false,
        trickle: false,
        stream: streamRef.current,
        config: webRtcConfig
      });
      
      peer.on('signal', signal => {
        sendMessage('signal', {
          room: `video_room_${roomId}`,
          peerId: from,
          signal,
          from: userInfoRef.current?.peerId
        });
      });
      
      peer.on('stream', stream => {
        setPeers(peers => ({
          ...peers,
          [from]: stream
        }));
      });
      
      peer.on('close', () => {
        removeVideoStream(from);
      });
      
      peer.on('error', err => {
        console.error('Peer error:', err);
        removeVideoStream(from);
      });
      
      peersRef.current[from] = { peer };
    }
    
    // Signal the peer
    peersRef.current[from].peer.signal(signal);
  };
  
  // Remove a video stream from the UI
  const removeVideoStream = (peerId) => {
    setPeers(peers => {
      const newPeers = { ...peers };
      delete newPeers[peerId];
      return newPeers;
    });
  };
  
  // Toggle audio
  const toggleAudio = () => {
    if (streamRef.current) {
      streamRef.current.getAudioTracks().forEach(track => {
        track.enabled = !track.enabled;
      });
      setIsAudioEnabled(!isAudioEnabled);
    }
  };
  
  // Toggle video
  const toggleVideo = () => {
    if (streamRef.current) {
      streamRef.current.getVideoTracks().forEach(track => {
        track.enabled = !track.enabled;
      });
      setIsVideoEnabled(!isVideoEnabled);
    }
  };
  
  // Toggle screen sharing
  const toggleScreenShare = async () => {
    if (isScreenSharing) {
      // Stop screen sharing
      if (screenShare) {
        screenShare.getTracks().forEach(track => track.stop());
      }
      
      // Switch back to camera stream for all peers
      Object.values(peersRef.current).forEach(({ peer }) => {
        streamRef.current.getTracks().forEach(track => {
          peer.replaceTrack(
            peer.streams[0].getVideoTracks()[0],
            track,
            peer.streams[0]
          );
        });
      });
      
      // Update state
      setScreenShare(null);
      setIsScreenSharing(false);
      
    } else {
      try {
        // Get screen share stream
        const screenStream = await navigator.mediaDevices.getDisplayMedia({
          video: true
        });
        
        // Replace video track with screen share track for all peers
        Object.values(peersRef.current).forEach(({ peer }) => {
          peer.replaceTrack(
            peer.streams[0].getVideoTracks()[0],
            screenStream.getVideoTracks()[0],
            peer.streams[0]
          );
        });
        
        // Handle stream end (user stops sharing)
        screenStream.getVideoTracks()[0].onended = () => {
          toggleScreenShare();
        };
        
        // Update state
        setScreenShare(screenStream);
        setIsScreenSharing(true);
        
      } catch (error) {
        console.error('Error sharing screen:', error);
        toast.error('Failed to share screen');
      }
    }
  };
  
  if (isJoining) {
    return (
      <div className="flex items-center justify-center h-screen bg-gray-900">
        <div className="text-center text-white">
          <div className="spinner mb-4"></div>
          <p className="text-xl">Joining video consultation...</p>
        </div>
      </div>
    );
  }
  
  if (joinError) {
    return (
      <div className="flex items-center justify-center h-screen bg-gray-900">
        <div className="text-center text-white p-8 bg-gray-800 rounded-lg max-w-md">
          <div className="text-red-500 text-5xl mb-4">⚠️</div>
          <h2 className="text-2xl font-bold mb-4">Failed to Join Consultation</h2>
          <p className="mb-6">{joinError}</p>
          <button 
            onClick={() => navigate('/appointments')}
            className="px-4 py-2 bg-blue-600 text-white rounded hover:bg-blue-700"
          >
            Return to Appointments
          </button>
        </div>
      </div>
    );
  }
  
  return (
    <div className="flex flex-col h-screen bg-gray-900">
      {/* Video Grid */}
      <div className="flex-1 grid grid-cols-1 md:grid-cols-2 gap-4 p-4 overflow-auto">
        {/* Local Video */}
        <div className="relative bg-black rounded-lg overflow-hidden">
          <video
            ref={localVideoRef}
            autoPlay
            muted
            playsInline
            className="w-full h-full object-cover"
          />
          <div className="absolute bottom-2 left-2 bg-black bg-opacity-50 px-2 py-1 rounded text-white text-sm">
            You {!isVideoEnabled && '(Video Off)'} {!isAudioEnabled && '(Muted)'}
          </div>
        </div>
        
        {/* Remote Videos */}
        {Object.entries(peers).map(([peerId, stream]) => (
          <div key={peerId} className="relative bg-black rounded-lg overflow-hidden">
            <video
              autoPlay
              playsInline
              className="w-full h-full object-cover"
              ref={video => {
                if (video && !video.srcObject) {
                  video.srcObject = stream;
                }
              }}
            />
            <div className="absolute bottom-2 left-2 bg-black bg-opacity-50 px-2 py-1 rounded text-white text-sm">
              {participants.find(p => p.peer_id === peerId)?.name || 'Participant'}
            </div>
          </div>
        ))}
      </div>
      
      {/* Controls */}
      <div className="bg-gray-800 p-4 flex items-center justify-center space-x-6">
        <button 
          onClick={toggleAudio}
          className={`p-3 rounded-full ${isAudioEnabled ? 'bg-gray-600' : 'bg-red-600'}`}
        >
          {isAudioEnabled ? <MicIcon /> : <MicOffIcon />}
        </button>
        
        <button 
          onClick={toggleVideo}
          className={`p-3 rounded-full ${isVideoEnabled ? 'bg-gray-600' : 'bg-red-600'}`}
        >
          {isVideoEnabled ? <VideocamIcon /> : <VideocamOffIcon />}
        </button>
        
        <button 
          onClick={toggleScreenShare}
          className={`p-3 rounded-full ${isScreenSharing ? 'bg-green-600' : 'bg-gray-600'}`}
        >
          {isScreenSharing ? <StopScreenShareIcon /> : <ScreenShareIcon />}
        </button>
        
        <button 
          onClick={() => setIsChatOpen(!isChatOpen)}
          className={`p-3 rounded-full ${isChatOpen ? 'bg-blue-600' : 'bg-gray-600'}`}
        >
          <ChatIcon />
        </button>
        
        <button 
          onClick={leaveRoom}
          className="p-3 rounded-full bg-red-600"
        >
          <CallEndIcon />
        </button>
      </div>
      
      {/* Chat Panel (if open) */}
      {isChatOpen && (
        <div className="absolute right-0 top-0 h-screen w-80 bg-gray-800 shadow-lg overflow-hidden flex flex-col">
          <div className="p-4 bg-gray-900 text-white font-bold">
            Chat
            <button 
              onClick={() => setIsChatOpen(false)}
              className="float-right"
            >
              &times;
            </button>
          </div>
          <div className="flex-1 p-4 overflow-auto bg-gray-800">
            {/* Chat messages would go here */}
          </div>
          <div className="p-4 bg-gray-900">
            <input 
              type="text"
              placeholder="Type a message..."
              className="w-full p-2 rounded bg-gray-700 text-white"
            />
          </div>
        </div>
      )}
    </div>
  );
};

export default VideoConsultation;
