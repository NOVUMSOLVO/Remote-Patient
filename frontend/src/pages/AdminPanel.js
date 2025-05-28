import React, { useState, useEffect } from 'react';
import { Users, Settings, Shield, Database, Activity, AlertTriangle, UserPlus, Edit3, Trash2, Search, Filter, Download, RefreshCw } from 'lucide-react';
import './AdminPanel.css';

const AdminPanel = () => {
  const [activeTab, setActiveTab] = useState('users');
  const [users, setUsers] = useState([]);
  const [systemSettings, setSystemSettings] = useState({});
  const [systemHealth, setSystemHealth] = useState({});
  const [auditLogs, setAuditLogs] = useState([]);
  const [loading, setLoading] = useState(true);
  const [searchTerm, setSearchTerm] = useState('');
  const [filterRole, setFilterRole] = useState('all');
  const [showUserModal, setShowUserModal] = useState(false);
  const [selectedUser, setSelectedUser] = useState(null);

  useEffect(() => {
    fetchData();
  }, [activeTab]);

  const fetchData = async () => {
    try {
      setLoading(true);
      await Promise.all([
        fetchUsers(),
        fetchSystemSettings(),
        fetchSystemHealth(),
        fetchAuditLogs()
      ]);
    } catch (error) {
      console.error('Error fetching data:', error);
    } finally {
      setLoading(false);
    }
  };

  const fetchUsers = async () => {
    // API call would go here
    const mockUsers = [
      {
        id: 1,
        name: 'Dr. Sarah Johnson',
        email: 'sarah.johnson@nhs.uk',
        role: 'doctor',
        status: 'active',
        lastLogin: new Date(Date.now() - 1000 * 60 * 30),
        patientsCount: 45,
        department: 'Cardiology',
        nhsId: 'NHS001234',
        permissions: ['view_patients', 'manage_patients', 'prescribe_medication']
      },
      {
        id: 2,
        name: 'Nurse Mary Williams',
        email: 'mary.williams@nhs.uk',
        role: 'nurse',
        status: 'active',
        lastLogin: new Date(Date.now() - 1000 * 60 * 60 * 2),
        patientsCount: 78,
        department: 'General Medicine',
        nhsId: 'NHS001235',
        permissions: ['view_patients', 'update_vitals', 'send_messages']
      },
      {
        id: 3,
        name: 'Admin John Smith',
        email: 'john.smith@nhs.uk',
        role: 'admin',
        status: 'active',
        lastLogin: new Date(Date.now() - 1000 * 60 * 60 * 4),
        patientsCount: 0,
        department: 'IT Administration',
        nhsId: 'NHS001236',
        permissions: ['full_access', 'user_management', 'system_settings']
      },
      {
        id: 4,
        name: 'Care Coordinator Emma Davis',
        email: 'emma.davis@nhs.uk',
        role: 'care_coordinator',
        status: 'inactive',
        lastLogin: new Date(Date.now() - 1000 * 60 * 60 * 24 * 7),
        patientsCount: 32,
        department: 'Care Coordination',
        nhsId: 'NHS001237',
        permissions: ['view_patients', 'coordinate_care', 'generate_reports']
      }
    ];
    setUsers(mockUsers);
  };

  const fetchSystemSettings = async () => {
    // API call would go here
    const mockSettings = {
      general: {
        systemName: 'NHS Remote Patient Monitoring',
        maintenanceMode: false,
        sessionTimeout: 30,
        maxLoginAttempts: 5,
        passwordExpiry: 90
      },
      security: {
        twoFactorAuth: true,
        passwordComplexity: 'high',
        encryptionLevel: 'AES-256',
        auditLogging: true,
        ipWhitelist: ['192.168.1.0/24', '10.0.0.0/8']
      },
      notifications: {
        emailNotifications: true,
        smsNotifications: true,
        pushNotifications: true,
        alertThresholds: {
          critical: 'immediate',
          high: '5 minutes',
          medium: '30 minutes',
          low: '2 hours'
        }
      },
      integration: {
        fhirEndpoint: 'https://api.nhs.uk/fhir',
        apiVersion: 'R4',
        dataSync: 'real-time',
        backupFrequency: 'daily'
      }
    };
    setSystemSettings(mockSettings);
  };

  const fetchSystemHealth = async () => {
    // API call would go here
    const mockHealth = {
      overall: 'healthy',
      uptime: '99.9%',
      lastRestart: new Date(Date.now() - 1000 * 60 * 60 * 24 * 15),
      services: [
        { name: 'API Server', status: 'healthy', responseTime: '145ms' },
        { name: 'Database', status: 'healthy', responseTime: '23ms' },
        { name: 'FHIR Integration', status: 'healthy', responseTime: '267ms' },
        { name: 'Notification Service', status: 'warning', responseTime: '456ms' },
        { name: 'File Storage', status: 'healthy', responseTime: '89ms' }
      ],
      resources: {
        cpu: 34,
        memory: 67,
        disk: 45,
        network: 23
      },
      alerts: [
        {
          id: 1,
          type: 'warning',
          message: 'Notification service response time above threshold',
          timestamp: new Date(Date.now() - 1000 * 60 * 30)
        },
        {
          id: 2,
          type: 'info',
          message: 'Scheduled backup completed successfully',
          timestamp: new Date(Date.now() - 1000 * 60 * 60 * 6)
        }
      ]
    };
    setSystemHealth(mockHealth);
  };

  const fetchAuditLogs = async () => {
    // API call would go here
    const mockLogs = [
      {
        id: 1,
        action: 'USER_LOGIN',
        user: 'sarah.johnson@nhs.uk',
        details: 'Successful login from 192.168.1.100',
        timestamp: new Date(Date.now() - 1000 * 60 * 15),
        category: 'authentication'
      },
      {
        id: 2,
        action: 'PATIENT_UPDATED',
        user: 'mary.williams@nhs.uk',
        details: 'Updated vital signs for patient NHS1234567890',
        timestamp: new Date(Date.now() - 1000 * 60 * 30),
        category: 'data'
      },
      {
        id: 3,
        action: 'ALERT_CREATED',
        user: 'system',
        details: 'Critical blood pressure alert for patient NHS0987654321',
        timestamp: new Date(Date.now() - 1000 * 60 * 45),
        category: 'alert'
      },
      {
        id: 4,
        action: 'USER_CREATED',
        user: 'john.smith@nhs.uk',
        details: 'Created new user account for Dr. Michael Brown',
        timestamp: new Date(Date.now() - 1000 * 60 * 60 * 2),
        category: 'user_management'
      }
    ];
    setAuditLogs(mockLogs);
  };

  const handleUserAction = async (action, userId, data = null) => {
    try {
      // API call would go here
      switch (action) {
        case 'create':
          console.log('Creating user:', data);
          break;
        case 'update':
          console.log('Updating user:', userId, data);
          break;
        case 'delete':
          console.log('Deleting user:', userId);
          setUsers(users.filter(user => user.id !== userId));
          break;
        case 'activate':
          setUsers(users.map(user => 
            user.id === userId ? { ...user, status: 'active' } : user
          ));
          break;
        case 'deactivate':
          setUsers(users.map(user => 
            user.id === userId ? { ...user, status: 'inactive' } : user
          ));
          break;
        default:
          break;
      }
    } catch (error) {
      console.error('Error performing user action:', error);
    }
  };

  const handleSettingsUpdate = async (category, settings) => {
    try {
      // API call would go here
      setSystemSettings(prev => ({
        ...prev,
        [category]: { ...prev[category], ...settings }
      }));
      console.log('Updated settings:', category, settings);
    } catch (error) {
      console.error('Error updating settings:', error);
    }
  };

  const filteredUsers = users.filter(user => {
    const matchesSearch = user.name.toLowerCase().includes(searchTerm.toLowerCase()) ||
                         user.email.toLowerCase().includes(searchTerm.toLowerCase()) ||
                         user.nhsId.toLowerCase().includes(searchTerm.toLowerCase());
    const matchesRole = filterRole === 'all' || user.role === filterRole;
    return matchesSearch && matchesRole;
  });

  const getRoleColor = (role) => {
    const colors = {
      admin: 'bg-purple-100 text-purple-800',
      doctor: 'bg-blue-100 text-blue-800',
      nurse: 'bg-green-100 text-green-800',
      care_coordinator: 'bg-orange-100 text-orange-800'
    };
    return colors[role] || 'bg-gray-100 text-gray-800';
  };

  const getStatusColor = (status) => {
    return status === 'active' ? 'text-green-600' : 'text-red-600';
  };

  const getServiceStatusColor = (status) => {
    const colors = {
      healthy: 'text-green-600 bg-green-100',
      warning: 'text-yellow-600 bg-yellow-100',
      error: 'text-red-600 bg-red-100'
    };
    return colors[status] || 'text-gray-600 bg-gray-100';
  };

  if (loading) {
    return (
      <div className="flex justify-center items-center h-64">
        <div className="animate-spin rounded-full h-32 w-32 border-b-2 border-blue-500"></div>
      </div>
    );
  }

  return (
    <div className="admin-panel">
      {/* Header */}
      <div className="admin-header">
        <h1 className="text-2xl font-bold text-gray-900 mb-6">System Administration</h1>
        
        {/* Tabs */}
        <div className="tabs-container">
          <button
            onClick={() => setActiveTab('users')}
            className={`tab-button ${activeTab === 'users' ? 'active' : ''}`}
          >
            <Users className="h-5 w-5 mr-2" />
            User Management
          </button>
          <button
            onClick={() => setActiveTab('settings')}
            className={`tab-button ${activeTab === 'settings' ? 'active' : ''}`}
          >
            <Settings className="h-5 w-5 mr-2" />
            System Settings
          </button>
          <button
            onClick={() => setActiveTab('health')}
            className={`tab-button ${activeTab === 'health' ? 'active' : ''}`}
          >
            <Activity className="h-5 w-5 mr-2" />
            System Health
          </button>
          <button
            onClick={() => setActiveTab('audit')}
            className={`tab-button ${activeTab === 'audit' ? 'active' : ''}`}
          >
            <Shield className="h-5 w-5 mr-2" />
            Audit Logs
          </button>
        </div>
      </div>

      {/* Content */}
      <div className="admin-content">
        {activeTab === 'users' && (
          <div className="users-management">
            {/* Users Header */}
            <div className="section-header">
              <div className="flex items-center justify-between mb-6">
                <h2 className="text-lg font-semibold text-gray-900">User Management</h2>
                <button
                  onClick={() => {
                    setSelectedUser(null);
                    setShowUserModal(true);
                  }}
                  className="flex items-center px-4 py-2 bg-blue-600 text-white rounded-md hover:bg-blue-700 transition-colors"
                >
                  <UserPlus className="h-4 w-4 mr-2" />
                  Add User
                </button>
              </div>

              {/* Filters */}
              <div className="filters bg-white p-4 rounded-lg shadow-sm mb-6">
                <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
                  <div className="relative">
                    <Search className="h-5 w-5 text-gray-400 absolute left-3 top-1/2 transform -translate-y-1/2" />
                    <input
                      type="text"
                      placeholder="Search users..."
                      value={searchTerm}
                      onChange={(e) => setSearchTerm(e.target.value)}
                      className="pl-10 pr-4 py-2 border border-gray-300 rounded-md focus:ring-2 focus:ring-blue-500 focus:border-transparent w-full"
                    />
                  </div>
                  <select
                    value={filterRole}
                    onChange={(e) => setFilterRole(e.target.value)}
                    className="px-3 py-2 border border-gray-300 rounded-md focus:ring-2 focus:ring-blue-500 focus:border-transparent"
                  >
                    <option value="all">All Roles</option>
                    <option value="admin">Admin</option>
                    <option value="doctor">Doctor</option>
                    <option value="nurse">Nurse</option>
                    <option value="care_coordinator">Care Coordinator</option>
                  </select>
                  <button
                    onClick={() => fetchUsers()}
                    className="flex items-center px-4 py-2 bg-gray-100 text-gray-700 rounded-md hover:bg-gray-200 transition-colors"
                  >
                    <RefreshCw className="h-4 w-4 mr-2" />
                    Refresh
                  </button>
                </div>
              </div>
            </div>

            {/* Users Table */}
            <div className="users-table bg-white rounded-lg shadow-sm overflow-hidden">
              <table className="w-full">
                <thead className="bg-gray-50">
                  <tr>
                    <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">User</th>
                    <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Role</th>
                    <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Status</th>
                    <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Last Login</th>
                    <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Patients</th>
                    <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Actions</th>
                  </tr>
                </thead>
                <tbody className="bg-white divide-y divide-gray-200">
                  {filteredUsers.map((user) => (
                    <tr key={user.id} className="hover:bg-gray-50">
                      <td className="px-6 py-4 whitespace-nowrap">
                        <div>
                          <div className="text-sm font-medium text-gray-900">{user.name}</div>
                          <div className="text-sm text-gray-500">{user.email}</div>
                          <div className="text-xs text-gray-400">{user.nhsId}</div>
                        </div>
                      </td>
                      <td className="px-6 py-4 whitespace-nowrap">
                        <span className={`inline-flex px-2 py-1 text-xs font-semibold rounded-full ${getRoleColor(user.role)}`}>
                          {user.role.replace('_', ' ')}
                        </span>
                      </td>
                      <td className="px-6 py-4 whitespace-nowrap">
                        <span className={`text-sm font-medium ${getStatusColor(user.status)}`}>
                          {user.status}
                        </span>
                      </td>
                      <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-500">
                        {user.lastLogin.toLocaleDateString()}
                      </td>
                      <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-500">
                        {user.patientsCount}
                      </td>
                      <td className="px-6 py-4 whitespace-nowrap text-sm font-medium">
                        <div className="flex items-center space-x-2">
                          <button
                            onClick={() => {
                              setSelectedUser(user);
                              setShowUserModal(true);
                            }}
                            className="text-blue-600 hover:text-blue-900"
                          >
                            <Edit3 className="h-4 w-4" />
                          </button>
                          <button
                            onClick={() => handleUserAction(user.status === 'active' ? 'deactivate' : 'activate', user.id)}
                            className={user.status === 'active' ? 'text-yellow-600 hover:text-yellow-900' : 'text-green-600 hover:text-green-900'}
                          >
                            {user.status === 'active' ? 'Deactivate' : 'Activate'}
                          </button>
                          <button
                            onClick={() => handleUserAction('delete', user.id)}
                            className="text-red-600 hover:text-red-900"
                          >
                            <Trash2 className="h-4 w-4" />
                          </button>
                        </div>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>
        )}

        {activeTab === 'settings' && (
          <div className="system-settings">
            <h2 className="text-lg font-semibold text-gray-900 mb-6">System Settings</h2>
            
            <div className="settings-sections space-y-6">
              {/* General Settings */}
              <div className="settings-section">
                <h3 className="text-md font-semibold text-gray-800 mb-4">General Settings</h3>
                <div className="bg-white p-6 rounded-lg shadow-sm">
                  <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
                    <div>
                      <label className="block text-sm font-medium text-gray-700 mb-2">System Name</label>
                      <input
                        type="text"
                        value={systemSettings.general?.systemName || ''}
                        onChange={(e) => handleSettingsUpdate('general', { systemName: e.target.value })}
                        className="w-full px-3 py-2 border border-gray-300 rounded-md focus:ring-2 focus:ring-blue-500 focus:border-transparent"
                      />
                    </div>
                    <div>
                      <label className="block text-sm font-medium text-gray-700 mb-2">Session Timeout (minutes)</label>
                      <input
                        type="number"
                        value={systemSettings.general?.sessionTimeout || ''}
                        onChange={(e) => handleSettingsUpdate('general', { sessionTimeout: parseInt(e.target.value) })}
                        className="w-full px-3 py-2 border border-gray-300 rounded-md focus:ring-2 focus:ring-blue-500 focus:border-transparent"
                      />
                    </div>
                    <div>
                      <label className="flex items-center">
                        <input
                          type="checkbox"
                          checked={systemSettings.general?.maintenanceMode || false}
                          onChange={(e) => handleSettingsUpdate('general', { maintenanceMode: e.target.checked })}
                          className="mr-2"
                        />
                        <span className="text-sm font-medium text-gray-700">Maintenance Mode</span>
                      </label>
                    </div>
                  </div>
                </div>
              </div>

              {/* Security Settings */}
              <div className="settings-section">
                <h3 className="text-md font-semibold text-gray-800 mb-4">Security Settings</h3>
                <div className="bg-white p-6 rounded-lg shadow-sm">
                  <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
                    <div>
                      <label className="flex items-center">
                        <input
                          type="checkbox"
                          checked={systemSettings.security?.twoFactorAuth || false}
                          onChange={(e) => handleSettingsUpdate('security', { twoFactorAuth: e.target.checked })}
                          className="mr-2"
                        />
                        <span className="text-sm font-medium text-gray-700">Two-Factor Authentication</span>
                      </label>
                    </div>
                    <div>
                      <label className="block text-sm font-medium text-gray-700 mb-2">Password Complexity</label>
                      <select
                        value={systemSettings.security?.passwordComplexity || ''}
                        onChange={(e) => handleSettingsUpdate('security', { passwordComplexity: e.target.value })}
                        className="w-full px-3 py-2 border border-gray-300 rounded-md focus:ring-2 focus:ring-blue-500 focus:border-transparent"
                      >
                        <option value="low">Low</option>
                        <option value="medium">Medium</option>
                        <option value="high">High</option>
                      </select>
                    </div>
                    <div>
                      <label className="flex items-center">
                        <input
                          type="checkbox"
                          checked={systemSettings.security?.auditLogging || false}
                          onChange={(e) => handleSettingsUpdate('security', { auditLogging: e.target.checked })}
                          className="mr-2"
                        />
                        <span className="text-sm font-medium text-gray-700">Audit Logging</span>
                      </label>
                    </div>
                  </div>
                </div>
              </div>
            </div>
          </div>
        )}

        {activeTab === 'health' && (
          <div className="system-health">
            <h2 className="text-lg font-semibold text-gray-900 mb-6">System Health</h2>
            
            {/* Overview */}
            <div className="health-overview mb-8">
              <div className="grid grid-cols-1 md:grid-cols-4 gap-6">
                <div className="health-metric">
                  <div className="flex items-center justify-between">
                    <div>
                      <p className="text-sm font-medium text-gray-600">Overall Status</p>
                      <p className={`text-2xl font-bold ${systemHealth.overall === 'healthy' ? 'text-green-600' : 'text-red-600'}`}>
                        {systemHealth.overall}
                      </p>
                    </div>
                    <Activity className="h-8 w-8 text-green-500" />
                  </div>
                </div>
                <div className="health-metric">
                  <div className="flex items-center justify-between">
                    <div>
                      <p className="text-sm font-medium text-gray-600">Uptime</p>
                      <p className="text-2xl font-bold text-gray-900">{systemHealth.uptime}</p>
                    </div>
                    <AlertTriangle className="h-8 w-8 text-blue-500" />
                  </div>
                </div>
                <div className="health-metric">
                  <div className="flex items-center justify-between">
                    <div>
                      <p className="text-sm font-medium text-gray-600">CPU Usage</p>
                      <p className="text-2xl font-bold text-gray-900">{systemHealth.resources?.cpu}%</p>
                    </div>
                    <div className="w-8 h-8 bg-gray-200 rounded-full flex items-center justify-center">
                      <div className={`w-6 h-6 rounded-full ${systemHealth.resources?.cpu > 80 ? 'bg-red-500' : 'bg-green-500'}`}></div>
                    </div>
                  </div>
                </div>
                <div className="health-metric">
                  <div className="flex items-center justify-between">
                    <div>
                      <p className="text-sm font-medium text-gray-600">Memory Usage</p>
                      <p className="text-2xl font-bold text-gray-900">{systemHealth.resources?.memory}%</p>
                    </div>
                    <Database className="h-8 w-8 text-purple-500" />
                  </div>
                </div>
              </div>
            </div>

            {/* Services Status */}
            <div className="services-status mb-8">
              <h3 className="text-md font-semibold text-gray-800 mb-4">Services Status</h3>
              <div className="bg-white rounded-lg shadow-sm overflow-hidden">
                <table className="w-full">
                  <thead className="bg-gray-50">
                    <tr>
                      <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Service</th>
                      <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Status</th>
                      <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Response Time</th>
                    </tr>
                  </thead>
                  <tbody className="bg-white divide-y divide-gray-200">
                    {systemHealth.services?.map((service, index) => (
                      <tr key={index}>
                        <td className="px-6 py-4 whitespace-nowrap text-sm font-medium text-gray-900">
                          {service.name}
                        </td>
                        <td className="px-6 py-4 whitespace-nowrap">
                          <span className={`inline-flex px-2 py-1 text-xs font-semibold rounded-full ${getServiceStatusColor(service.status)}`}>
                            {service.status}
                          </span>
                        </td>
                        <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-500">
                          {service.responseTime}
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </div>
          </div>
        )}

        {activeTab === 'audit' && (
          <div className="audit-logs">
            <div className="flex items-center justify-between mb-6">
              <h2 className="text-lg font-semibold text-gray-900">Audit Logs</h2>
              <button
                onClick={() => {/* Export audit logs */}}
                className="flex items-center px-4 py-2 bg-blue-600 text-white rounded-md hover:bg-blue-700 transition-colors"
              >
                <Download className="h-4 w-4 mr-2" />
                Export Logs
              </button>
            </div>
            
            <div className="bg-white rounded-lg shadow-sm overflow-hidden">
              <table className="w-full">
                <thead className="bg-gray-50">
                  <tr>
                    <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Timestamp</th>
                    <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Action</th>
                    <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">User</th>
                    <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Details</th>
                    <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Category</th>
                  </tr>
                </thead>
                <tbody className="bg-white divide-y divide-gray-200">
                  {auditLogs.map((log) => (
                    <tr key={log.id} className="hover:bg-gray-50">
                      <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-500">
                        {log.timestamp.toLocaleString()}
                      </td>
                      <td className="px-6 py-4 whitespace-nowrap text-sm font-medium text-gray-900">
                        {log.action}
                      </td>
                      <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-500">
                        {log.user}
                      </td>
                      <td className="px-6 py-4 text-sm text-gray-500">
                        {log.details}
                      </td>
                      <td className="px-6 py-4 whitespace-nowrap">
                        <span className="inline-flex px-2 py-1 text-xs font-semibold rounded-full bg-blue-100 text-blue-800">
                          {log.category}
                        </span>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>
        )}
      </div>
    </div>
  );
};

export default AdminPanel;
