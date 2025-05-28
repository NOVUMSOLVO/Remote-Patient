import { useState, useEffect, useCallback, useRef } from 'react';
import { io } from 'socket.io-client';
import toast from 'react-hot-toast';

const useWebSocket = (token) => {
  const [socket, setSocket] = useState(null);
  const [isConnected, setIsConnected] = useState(false);
  const [connectionError, setConnectionError] = useState(null);
  const reconnectAttempts = useRef(0);
  const maxReconnectAttempts = 5;

  const connect = useCallback(() => {
    if (!token) return;

    const newSocket = io(process.env.REACT_APP_WS_URL || 'http://localhost:5000', {
      auth: {
        token: token
      },
      transports: ['websocket', 'polling'],
      timeout: 20000,
      forceNew: true
    });

    newSocket.on('connect', () => {
      console.log('WebSocket connected');
      setIsConnected(true);
      setConnectionError(null);
      reconnectAttempts.current = 0;
      toast.success('Real-time connection established');
    });

    newSocket.on('disconnect', (reason) => {
      console.log('WebSocket disconnected:', reason);
      setIsConnected(false);
      
      if (reason === 'io server disconnect') {
        // Server disconnected the socket, need to reconnect manually
        setTimeout(() => {
          if (reconnectAttempts.current < maxReconnectAttempts) {
            reconnectAttempts.current++;
            connect();
          }
        }, 1000 * reconnectAttempts.current);
      }
    });

    newSocket.on('connect_error', (error) => {
      console.error('WebSocket connection error:', error);
      setConnectionError(error.message);
      setIsConnected(false);
      toast.error('Connection error: ' + error.message);
    });

    newSocket.on('connection_status', (data) => {
      console.log('Connection status:', data);
    });

    newSocket.on('error', (error) => {
      console.error('WebSocket error:', error);
      toast.error(error.message || 'WebSocket error occurred');
    });

    setSocket(newSocket);

    return newSocket;
  }, [token]);

  const disconnect = useCallback(() => {
    if (socket) {
      socket.disconnect();
      setSocket(null);
      setIsConnected(false);
    }
  }, [socket]);

  const joinRoom = useCallback((room) => {
    if (socket && isConnected) {
      socket.emit('join_alert_room', { room });
    }
  }, [socket, isConnected]);

  const leaveRoom = useCallback((room) => {
    if (socket && isConnected) {
      socket.emit('leave_alert_room', { room });
    }
  }, [socket, isConnected]);

  const acknowledgeAlert = useCallback((alertId) => {
    if (socket && isConnected) {
      socket.emit('acknowledge_alert', { alert_id: alertId });
    }
  }, [socket, isConnected]);

  useEffect(() => {
    if (token) {
      connect();
    }

    return () => {
      disconnect();
    };
  }, [token, connect, disconnect]);

  return {
    socket,
    isConnected,
    connectionError,
    connect,
    disconnect,
    joinRoom,
    leaveRoom,
    acknowledgeAlert
  };
};

export default useWebSocket;
