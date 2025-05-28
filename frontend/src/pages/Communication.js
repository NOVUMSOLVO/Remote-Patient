import React, { useState, useEffect } from 'react';
import { MessageSquare, Send, Phone, Video, Mail, Bell, Settings, Users, Search, Filter, Calendar, Paperclip, Smile } from 'lucide-react';
import './Communication.css';

const Communication = () => {
  const [activeTab, setActiveTab] = useState('messages');
  const [selectedConversation, setSelectedConversation] = useState(null);
  const [conversations, setConversations] = useState([]);
  const [messages, setMessages] = useState([]);
  const [newMessage, setNewMessage] = useState('');
  const [searchTerm, setSearchTerm] = useState('');
  const [loading, setLoading] = useState(true);
  const [notifications, setNotifications] = useState([]);

  useEffect(() => {
    fetchConversations();
    fetchNotifications();
  }, []);

  useEffect(() => {
    if (selectedConversation) {
      fetchMessages(selectedConversation.id);
    }
  }, [selectedConversation]);

  const fetchConversations = async () => {
    try {
      setLoading(true);
      // API call would go here
      const mockConversations = [
        {
          id: 1,
          type: 'patient',
          name: 'John Smith',
          nhsNumber: '1234567890',
          avatar: null,
          lastMessage: 'Thank you for the medication reminder',
          lastMessageTime: new Date(Date.now() - 1000 * 60 * 30),
          unreadCount: 2,
          status: 'online',
          priority: 'normal'
        },
        {
          id: 2,
          type: 'provider',
          name: 'Dr. Sarah Johnson',
          nhsNumber: null,
          avatar: null,
          lastMessage: 'Patient requires immediate attention',
          lastMessageTime: new Date(Date.now() - 1000 * 60 * 60),
          unreadCount: 1,
          status: 'away',
          priority: 'urgent'
        },
        {
          id: 3,
          type: 'patient',
          name: 'Mary Brown',
          nhsNumber: '0987654321',
          avatar: null,
          lastMessage: 'My blood pressure readings today',
          lastMessageTime: new Date(Date.now() - 1000 * 60 * 60 * 2),
          unreadCount: 0,
          status: 'offline',
          priority: 'normal'
        },
        {
          id: 4,
          type: 'group',
          name: 'Cardiology Team',
          nhsNumber: null,
          avatar: null,
          lastMessage: 'Weekly team meeting scheduled',
          lastMessageTime: new Date(Date.now() - 1000 * 60 * 60 * 4),
          unreadCount: 0,
          status: 'online',
          priority: 'normal'
        }
      ];
      setConversations(mockConversations);
    } catch (error) {
      console.error('Error fetching conversations:', error);
    } finally {
      setLoading(false);
    }
  };

  const fetchMessages = async (conversationId) => {
    try {
      // API call would go here
      const mockMessages = [
        {
          id: 1,
          conversationId,
          senderId: conversationId === 1 ? 1 : 2,
          senderName: conversationId === 1 ? 'John Smith' : 'Dr. Sarah Johnson',
          content: 'Hello, I have a question about my medication schedule.',
          timestamp: new Date(Date.now() - 1000 * 60 * 60 * 2),
          type: 'text',
          isFromMe: false,
          attachments: []
        },
        {
          id: 2,
          conversationId,
          senderId: 'me',
          senderName: 'You',
          content: 'Hi! I\'d be happy to help with your medication questions. What would you like to know?',
          timestamp: new Date(Date.now() - 1000 * 60 * 60),
          type: 'text',
          isFromMe: true,
          attachments: []
        },
        {
          id: 3,
          conversationId,
          senderId: conversationId === 1 ? 1 : 2,
          senderName: conversationId === 1 ? 'John Smith' : 'Dr. Sarah Johnson',
          content: 'Should I take my blood pressure medication before or after meals?',
          timestamp: new Date(Date.now() - 1000 * 60 * 30),
          type: 'text',
          isFromMe: false,
          attachments: []
        },
        {
          id: 4,
          conversationId,
          senderId: 'me',
          senderName: 'You',
          content: 'Your medication should be taken 30 minutes before meals for best absorption. Please continue with your current schedule.',
          timestamp: new Date(Date.now() - 1000 * 60 * 15),
          type: 'text',
          isFromMe: true,
          attachments: []
        }
      ];
      setMessages(mockMessages);
    } catch (error) {
      console.error('Error fetching messages:', error);
    }
  };

  const fetchNotifications = async () => {
    try {
      // API call would go here
      const mockNotifications = [
        {
          id: 1,
          type: 'message',
          title: 'New message from John Smith',
          content: 'Thank you for the medication reminder',
          timestamp: new Date(Date.now() - 1000 * 60 * 30),
          read: false
        },
        {
          id: 2,
          type: 'appointment',
          title: 'Appointment reminder',
          content: 'Video consultation with Dr. Sarah Johnson in 1 hour',
          timestamp: new Date(Date.now() - 1000 * 60 * 60),
          read: false
        },
        {
          id: 3,
          type: 'alert',
          title: 'Patient alert',
          content: 'High blood pressure reading for Mary Brown',
          timestamp: new Date(Date.now() - 1000 * 60 * 60 * 2),
          read: true
        }
      ];
      setNotifications(mockNotifications);
    } catch (error) {
      console.error('Error fetching notifications:', error);
    }
  };

  const sendMessage = async () => {
    if (!newMessage.trim() || !selectedConversation) return;

    const message = {
      id: Date.now(),
      conversationId: selectedConversation.id,
      senderId: 'me',
      senderName: 'You',
      content: newMessage,
      timestamp: new Date(),
      type: 'text',
      isFromMe: true,
      attachments: []
    };

    setMessages(prev => [...prev, message]);
    setNewMessage('');

    // Update conversation last message
    setConversations(prev => prev.map(conv =>
      conv.id === selectedConversation.id
        ? { ...conv, lastMessage: newMessage, lastMessageTime: new Date() }
        : conv
    ));

    try {
      // API call would go here
    } catch (error) {
      console.error('Error sending message:', error);
    }
  };

  const startVideoCall = async (conversationId) => {
    try {
      // Video call integration would go here
      console.log(`Starting video call with conversation ${conversationId}`);
    } catch (error) {
      console.error('Error starting video call:', error);
    }
  };

  const startVoiceCall = async (conversationId) => {
    try {
      // Voice call integration would go here
      console.log(`Starting voice call with conversation ${conversationId}`);
    } catch (error) {
      console.error('Error starting voice call:', error);
    }
  };

  const formatTimestamp = (timestamp) => {
    const now = new Date();
    const diff = now - timestamp;
    const minutes = Math.floor(diff / (1000 * 60));
    const hours = Math.floor(diff / (1000 * 60 * 60));
    const days = Math.floor(diff / (1000 * 60 * 60 * 24));

    if (minutes < 1) return 'Just now';
    if (minutes < 60) return `${minutes}m ago`;
    if (hours < 24) return `${hours}h ago`;
    if (days < 7) return `${days}d ago`;
    return timestamp.toLocaleDateString();
  };

  const getStatusColor = (status) => {
    switch (status) {
      case 'online': return 'bg-green-400';
      case 'away': return 'bg-yellow-400';
      case 'offline': return 'bg-gray-400';
      default: return 'bg-gray-400';
    }
  };

  const filteredConversations = conversations.filter(conv =>
    conv.name.toLowerCase().includes(searchTerm.toLowerCase()) ||
    (conv.nhsNumber && conv.nhsNumber.includes(searchTerm))
  );

  if (loading) {
    return (
      <div className="flex justify-center items-center h-64">
        <div className="animate-spin rounded-full h-32 w-32 border-b-2 border-blue-500"></div>
      </div>
    );
  }

  return (
    <div className="communication-container">
      {/* Header */}
      <div className="communication-header">
        <h1 className="text-2xl font-bold text-gray-900 mb-6">Communication Center</h1>
        
        {/* Tabs */}
        <div className="tabs-container">
          <button
            onClick={() => setActiveTab('messages')}
            className={`tab-button ${activeTab === 'messages' ? 'active' : ''}`}
          >
            <MessageSquare className="h-5 w-5 mr-2" />
            Messages
          </button>
          <button
            onClick={() => setActiveTab('notifications')}
            className={`tab-button ${activeTab === 'notifications' ? 'active' : ''}`}
          >
            <Bell className="h-5 w-5 mr-2" />
            Notifications
            {notifications.filter(n => !n.read).length > 0 && (
              <span className="ml-2 bg-red-500 text-white text-xs px-2 py-1 rounded-full">
                {notifications.filter(n => !n.read).length}
              </span>
            )}
          </button>
        </div>
      </div>

      {activeTab === 'messages' ? (
        <div className="messages-layout">
          {/* Conversations List */}
          <div className="conversations-panel">
            <div className="conversations-header">
              <div className="relative mb-4">
                <Search className="h-5 w-5 text-gray-400 absolute left-3 top-1/2 transform -translate-y-1/2" />
                <input
                  type="text"
                  placeholder="Search conversations..."
                  value={searchTerm}
                  onChange={(e) => setSearchTerm(e.target.value)}
                  className="pl-10 pr-4 py-2 border border-gray-300 rounded-md focus:ring-2 focus:ring-blue-500 focus:border-transparent w-full"
                />
              </div>
            </div>

            <div className="conversations-list">
              {filteredConversations.map((conversation) => (
                <div
                  key={conversation.id}
                  onClick={() => setSelectedConversation(conversation)}
                  className={`conversation-item ${selectedConversation?.id === conversation.id ? 'selected' : ''}`}
                >
                  <div className="flex items-center space-x-3">
                    <div className="relative">
                      <div className="w-12 h-12 bg-gray-300 rounded-full flex items-center justify-center">
                        {conversation.type === 'group' ? (
                          <Users className="h-6 w-6 text-gray-600" />
                        ) : (
                          <span className="text-lg font-semibold text-gray-600">
                            {conversation.name.split(' ').map(n => n[0]).join('')}
                          </span>
                        )}
                      </div>
                      <div className={`absolute bottom-0 right-0 w-3 h-3 rounded-full border-2 border-white ${getStatusColor(conversation.status)}`}></div>
                    </div>
                    
                    <div className="flex-1 min-w-0">
                      <div className="flex items-center justify-between">
                        <h3 className="text-sm font-semibold text-gray-900 truncate">
                          {conversation.name}
                        </h3>
                        <span className="text-xs text-gray-500">
                          {formatTimestamp(conversation.lastMessageTime)}
                        </span>
                      </div>
                      <div className="flex items-center justify-between">
                        <p className="text-sm text-gray-600 truncate">
                          {conversation.lastMessage}
                        </p>
                        {conversation.unreadCount > 0 && (
                          <span className="bg-blue-500 text-white text-xs px-2 py-1 rounded-full">
                            {conversation.unreadCount}
                          </span>
                        )}
                      </div>
                      {conversation.nhsNumber && (
                        <p className="text-xs text-gray-500">NHS: {conversation.nhsNumber}</p>
                      )}
                    </div>
                  </div>
                </div>
              ))}
            </div>
          </div>

          {/* Messages Panel */}
          <div className="messages-panel">
            {selectedConversation ? (
              <>
                {/* Conversation Header */}
                <div className="conversation-header">
                  <div className="flex items-center space-x-3">
                    <div className="relative">
                      <div className="w-10 h-10 bg-gray-300 rounded-full flex items-center justify-center">
                        {selectedConversation.type === 'group' ? (
                          <Users className="h-5 w-5 text-gray-600" />
                        ) : (
                          <span className="text-sm font-semibold text-gray-600">
                            {selectedConversation.name.split(' ').map(n => n[0]).join('')}
                          </span>
                        )}
                      </div>
                      <div className={`absolute bottom-0 right-0 w-3 h-3 rounded-full border-2 border-white ${getStatusColor(selectedConversation.status)}`}></div>
                    </div>
                    <div>
                      <h3 className="text-lg font-semibold text-gray-900">{selectedConversation.name}</h3>
                      {selectedConversation.nhsNumber && (
                        <p className="text-sm text-gray-500">NHS: {selectedConversation.nhsNumber}</p>
                      )}
                    </div>
                  </div>
                  
                  <div className="flex items-center space-x-2">
                    <button
                      onClick={() => startVoiceCall(selectedConversation.id)}
                      className="p-2 text-gray-600 hover:text-blue-600 hover:bg-blue-50 rounded-md transition-colors"
                    >
                      <Phone className="h-5 w-5" />
                    </button>
                    <button
                      onClick={() => startVideoCall(selectedConversation.id)}
                      className="p-2 text-gray-600 hover:text-blue-600 hover:bg-blue-50 rounded-md transition-colors"
                    >
                      <Video className="h-5 w-5" />
                    </button>
                    <button className="p-2 text-gray-600 hover:text-blue-600 hover:bg-blue-50 rounded-md transition-colors">
                      <Settings className="h-5 w-5" />
                    </button>
                  </div>
                </div>

                {/* Messages List */}
                <div className="messages-list">
                  {messages.map((message) => (
                    <div
                      key={message.id}
                      className={`message ${message.isFromMe ? 'from-me' : 'from-other'}`}
                    >
                      <div className="message-content">
                        <p>{message.content}</p>
                        <span className="message-time">
                          {message.timestamp.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })}
                        </span>
                      </div>
                    </div>
                  ))}
                </div>

                {/* Message Input */}
                <div className="message-input-container">
                  <div className="flex items-center space-x-2">
                    <button className="p-2 text-gray-600 hover:text-blue-600 hover:bg-blue-50 rounded-md transition-colors">
                      <Paperclip className="h-5 w-5" />
                    </button>
                    <div className="flex-1 relative">
                      <input
                        type="text"
                        value={newMessage}
                        onChange={(e) => setNewMessage(e.target.value)}
                        onKeyPress={(e) => e.key === 'Enter' && sendMessage()}
                        placeholder="Type a message..."
                        className="w-full px-4 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-blue-500 focus:border-transparent"
                      />
                    </div>
                    <button className="p-2 text-gray-600 hover:text-blue-600 hover:bg-blue-50 rounded-md transition-colors">
                      <Smile className="h-5 w-5" />
                    </button>
                    <button
                      onClick={sendMessage}
                      disabled={!newMessage.trim()}
                      className="px-4 py-2 bg-blue-600 text-white rounded-lg hover:bg-blue-700 disabled:opacity-50 disabled:cursor-not-allowed transition-colors"
                    >
                      <Send className="h-5 w-5" />
                    </button>
                  </div>
                </div>
              </>
            ) : (
              <div className="no-conversation-selected">
                <MessageSquare className="h-12 w-12 text-gray-400 mx-auto mb-4" />
                <p className="text-gray-500 text-center">Select a conversation to start messaging</p>
              </div>
            )}
          </div>
        </div>
      ) : (
        /* Notifications Panel */
        <div className="notifications-panel">
          <div className="notifications-header">
            <div className="flex items-center justify-between mb-4">
              <h2 className="text-lg font-semibold text-gray-900">Notifications</h2>
              <button className="text-sm text-blue-600 hover:text-blue-800">
                Mark all as read
              </button>
            </div>
          </div>

          <div className="notifications-list">
            {notifications.map((notification) => (
              <div
                key={notification.id}
                className={`notification-item ${!notification.read ? 'unread' : ''}`}
              >
                <div className="flex items-start space-x-3">
                  <div className={`notification-icon ${notification.type}`}>
                    {notification.type === 'message' && <MessageSquare className="h-5 w-5" />}
                    {notification.type === 'appointment' && <Calendar className="h-5 w-5" />}
                    {notification.type === 'alert' && <Bell className="h-5 w-5" />}
                  </div>
                  <div className="flex-1">
                    <h3 className="text-sm font-semibold text-gray-900">{notification.title}</h3>
                    <p className="text-sm text-gray-600">{notification.content}</p>
                    <span className="text-xs text-gray-500">{formatTimestamp(notification.timestamp)}</span>
                  </div>
                </div>
              </div>
            ))}
          </div>
        </div>
      )}
    </div>
  );
};

export default Communication;
