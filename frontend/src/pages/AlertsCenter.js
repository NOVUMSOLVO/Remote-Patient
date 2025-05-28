import React, { useState, useEffect, useCallback } from 'react';
import { Bell, AlertTriangle, Info, CheckCircle, X, Filter, Search, Calendar, Settings, Wifi, WifiOff } from 'lucide-react';
import { toast } from 'react-hot-toast';
import { useWebSocket } from '../hooks/useWebSocket';
import './AlertsCenter.css';

const AlertsCenter = () => {
  const [alerts, setAlerts] = useState([]);
  const [filteredAlerts, setFilteredAlerts] = useState([]);
  const [loading, setLoading] = useState(true);
  const [filterType, setFilterType] = useState('all');
  const [filterSeverity, setFilterSeverity] = useState('all');
  const [searchTerm, setSearchTerm] = useState('');
  const [dateFilter, setDateFilter] = useState('all');
  const [alertRules, setAlertRules] = useState([]);
  const [showRuleModal, setShowRuleModal] = useState(false);

  // Use the WebSocket hook for real-time communication
  const { 
    isConnected, 
    connectionError, 
    sendMessage, 
    joinRoom, 
    leaveRoom 
  } = useWebSocket({
    onNewAlert: (alertData) => {
      setAlerts(prev => [alertData.alert, ...prev]);
      toast.success(`New ${alertData.alert.severity} alert: ${alertData.alert.title}`);
    },
    onAlertAcknowledged: (data) => {
      setAlerts(prev => prev.map(alert => 
        alert.id === data.alert_id ? { ...alert, acknowledged: true } : alert
      ));
      toast.info('Alert acknowledged');
    },
    onAlertResolved: (data) => {
      setAlerts(prev => prev.filter(alert => alert.id !== data.alert.id));
      toast.success('Alert resolved');
    },
    onAlertEscalated: (data) => {
      setAlerts(prev => prev.map(alert => 
        alert.id === data.alert_id ? { ...alert, escalationLevel: data.escalation_level } : alert
      ));
      toast.warning('Alert escalated');
    },
    onNotification: (data) => {
      toast(data.notification.message, { 
        icon: data.notification.type === 'alert_resolved' ? '✅' : '🔔' 
      });
    }
  });

  useEffect(() => {
    fetchAlerts();
    fetchAlertRules();
    
    // Join the alerts room for real-time updates
    if (isConnected) {
      joinRoom('alerts_general');
    }
    
    return () => {
      if (isConnected) {
        leaveRoom('alerts_general');
      }
    };
  }, [isConnected, joinRoom, leaveRoom]);

  useEffect(() => {
    applyFilters();
  }, [alerts, filterType, filterSeverity, searchTerm, dateFilter]);



  const fetchAlertRules = async () => {
    try {
      // API call to fetch alert rules
      const mockRules = [
        {
          id: 1,
          name: 'Critical Blood Pressure',
          condition: 'systolic > 180 OR diastolic > 110',
          severity: 'high',
          enabled: true,
          actions: ['notify_gp', 'contact_patient']
        },
        {
          id: 2,
          name: 'Low Battery Warning',
          condition: 'battery_level < 20',
          severity: 'medium',
          enabled: true,
          actions: ['notify_patient']
        }
      ];
      setAlertRules(mockRules);
    } catch (error) {
      console.error('Error fetching alert rules:', error);
    }
  };

  const fetchAlerts = async () => {
    try {
      setLoading(true);
      
      // Request notification permission
      if (Notification.permission === 'default') {
        await Notification.requestPermission();
      }
      
      // API call would go here - for now using enhanced mock data
      const mockAlerts = [
        {
          id: 1,
          type: 'vital_signs',
          severity: 'high',
          title: 'Critical Blood Pressure Reading',
          message: 'Patient John Smith (NHS: 1234567890) has blood pressure of 180/110 mmHg',
          patientName: 'John Smith',
          nhsNumber: '1234567890',
          timestamp: new Date(Date.now() - 1000 * 60 * 30),
          acknowledged: false,
          deviceId: 'BP001',
          actions: ['contact_patient', 'escalate_to_gp', 'schedule_appointment'],
          escalationLevel: 1,
          autoResolved: false,
          relatedData: {
            systolic: 180,
            diastolic: 110,
            heartRate: 95
          }
        },
        {
          id: 2,
          type: 'device',
          severity: 'medium',
          title: 'Device Battery Low',
          message: 'Blood pressure monitor BP002 battery level at 15%',
          patientName: 'Mary Johnson',
          nhsNumber: '0987654321',
          timestamp: new Date(Date.now() - 1000 * 60 * 60 * 2),
          acknowledged: true,
          deviceId: 'BP002',
          actions: ['replace_battery', 'contact_patient'],
          escalationLevel: 0,
          autoResolved: false,
          relatedData: {
            batteryLevel: 15,
            lastReading: new Date(Date.now() - 1000 * 60 * 60)
          }
        },
        {
          id: 3,
          type: 'medication',
          severity: 'low',
          title: 'Medication Reminder',
          message: 'Patient David Brown missed morning medication dose',
          patientName: 'David Brown',
          nhsNumber: '1122334455',
          timestamp: new Date(Date.now() - 1000 * 60 * 60 * 4),
          acknowledged: false,
          deviceId: null,
          actions: ['send_reminder', 'contact_patient'],
          escalationLevel: 0,
          autoResolved: false,
          relatedData: {
            medicationName: 'Lisinopril',
            scheduledTime: '08:00',
            missedDoses: 1
          }
        },
        {
          id: 4,
          type: 'system',
          severity: 'low',
          title: 'System Maintenance Completed',
          message: 'Scheduled maintenance for FHIR integration completed successfully',
          patientName: null,
          nhsNumber: null,
          timestamp: new Date(Date.now() - 1000 * 60 * 60 * 6),
          acknowledged: true,
          deviceId: null,
          actions: [],
          escalationLevel: 0,
          autoResolved: true,
          relatedData: {}
        }
      ];
      setAlerts(mockAlerts);
    } catch (error) {
      console.error('Error fetching alerts:', error);
    } finally {
      setLoading(false);
    }
  };

  const applyFilters = () => {
    let filtered = [...alerts];

    // Filter by type
    if (filterType !== 'all') {
      filtered = filtered.filter(alert => alert.type === filterType);
    }

    // Filter by severity
    if (filterSeverity !== 'all') {
      filtered = filtered.filter(alert => alert.severity === filterSeverity);
    }

    // Filter by search term
    if (searchTerm) {
      filtered = filtered.filter(alert =>
        alert.title.toLowerCase().includes(searchTerm.toLowerCase()) ||
        alert.message.toLowerCase().includes(searchTerm.toLowerCase()) ||
        (alert.patientName && alert.patientName.toLowerCase().includes(searchTerm.toLowerCase())) ||
        (alert.nhsNumber && alert.nhsNumber.includes(searchTerm))
      );
    }

    // Filter by date
    if (dateFilter !== 'all') {
      const now = new Date();
      const cutoff = new Date();
      
      switch (dateFilter) {
        case 'today':
          cutoff.setHours(0, 0, 0, 0);
          break;
        case 'week':
          cutoff.setDate(now.getDate() - 7);
          break;
        case 'month':
          cutoff.setMonth(now.getMonth() - 1);
          break;
        default:
          break;
      }
      
      if (dateFilter !== 'all') {
        filtered = filtered.filter(alert => alert.timestamp >= cutoff);
      }
    }

    setFilteredAlerts(filtered);
  };

  const getSeverityIcon = (severity) => {
    switch (severity) {
      case 'high':
        return <AlertTriangle className="h-5 w-5 text-red-500" />;
      case 'medium':
        return <Info className="h-5 w-5 text-yellow-500" />;
      case 'low':
        return <Bell className="h-5 w-5 text-blue-500" />;
      default:
        return <Info className="h-5 w-5 text-gray-500" />;
    }
  };

  const getSeverityColor = (severity) => {
    switch (severity) {
      case 'high':
        return 'border-l-red-500 bg-red-50';
      case 'medium':
        return 'border-l-yellow-500 bg-yellow-50';
      case 'low':
        return 'border-l-blue-500 bg-blue-50';
      default:
        return 'border-l-gray-500 bg-gray-50';
    }
  };

  const handleAcknowledge = async (alertId) => {
    try {
      // Send WebSocket message for real-time updates
      if (sendMessage) {
        sendMessage('acknowledge_alert', {
          alert_id: alertId
        });
      }
      
      // API call to backend
      const response = await fetch(`${process.env.REACT_APP_BACKEND_URL || 'http://localhost:5000'}/api/alerts/${alertId}/acknowledge`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${localStorage.getItem('token')}`
        }
      });

      if (response.ok) {
        setAlerts(prev => prev.map(alert =>
          alert.id === alertId ? { ...alert, acknowledged: true } : alert
        ));
        toast.success('Alert acknowledged successfully');
      } else {
        const errorData = await response.json();
        throw new Error(errorData.message || 'Failed to acknowledge alert');
      }
    } catch (error) {
      console.error('Error acknowledging alert:', error);
      toast.error('Failed to acknowledge alert. Please try again.');
    }
  };

  const handleAction = async (alertId, action) => {
    try {
      console.log(`Executing action ${action} for alert ${alertId}`);
      
      // Send WebSocket message for real-time updates
      if (sendMessage) {
        sendMessage('alert_action', {
          alert_id: alertId,
          action: action
        });
      }
      
      // API call to backend
      const response = await fetch(`${process.env.REACT_APP_BACKEND_URL || 'http://localhost:5000'}/api/alerts/${alertId}/actions`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${localStorage.getItem('token')}`
        },
        body: JSON.stringify({ action })
      });

      if (response.ok) {
        // Update alert status based on action
        setAlerts(prev => prev.map(alert => {
          if (alert.id === alertId) {
            const updatedAlert = { ...alert };
            
            switch (action) {
              case 'escalate_to_gp':
                updatedAlert.escalationLevel = Math.min(alert.escalationLevel + 1, 3);
                break;
              case 'schedule_appointment':
                updatedAlert.actions = alert.actions.filter(a => a !== 'schedule_appointment');
                break;
              case 'contact_patient':
                updatedAlert.actions = alert.actions.filter(a => a !== 'contact_patient');
                break;
              default:
                break;
            }
            
            return updatedAlert;
          }
          return alert;
        }));

        // Show success message
        toast.success(`Action "${getActionLabel(action)}" completed successfully`);
      } else {
        const errorData = await response.json();
        throw new Error(errorData.message || 'Failed to execute action');
      }
    } catch (error) {
      console.error('Error executing action:', error);
      toast.error('Failed to execute action. Please try again.');
    }
  };

  const handleBulkAction = async (selectedAlerts, action) => {
    try {
      const promises = selectedAlerts.map(alertId => 
        handleAction(alertId, action)
      );
      await Promise.all(promises);
      toast.success(`Bulk action completed for ${selectedAlerts.length} alerts`);
    } catch (error) {
      console.error('Error executing bulk action:', error);
      toast.error('Failed to execute bulk action');
    }
  };



  const formatTimestamp = (timestamp) => {
    const now = new Date();
    const diff = now - timestamp;
    const minutes = Math.floor(diff / (1000 * 60));
    const hours = Math.floor(diff / (1000 * 60 * 60));
    const days = Math.floor(diff / (1000 * 60 * 60 * 24));

    if (minutes < 60) {
      return `${minutes}m ago`;
    } else if (hours < 24) {
      return `${hours}h ago`;
    } else {
      return `${days}d ago`;
    }
  };

  const getActionLabel = (action) => {
    const labels = {
      contact_patient: 'Contact Patient',
      escalate_to_gp: 'Escalate to GP',
      schedule_appointment: 'Schedule Appointment',
      replace_battery: 'Replace Battery',
      send_reminder: 'Send Reminder',
      notify_gp: 'Notify GP',
      notify_patient: 'Notify Patient'
    };
    return labels[action] || action;
  };

  const AlertRuleModal = () => (
    <div className={`fixed inset-0 bg-black bg-opacity-50 z-50 ${showRuleModal ? 'block' : 'hidden'}`}>
      <div className="flex items-center justify-center min-h-screen p-4">
        <div className="bg-white rounded-lg shadow-xl max-w-2xl w-full max-h-[90vh] overflow-auto">
          <div className="p-6">
            <div className="flex justify-between items-center mb-4">
              <h2 className="text-xl font-bold text-gray-900">Alert Rules Configuration</h2>
              <button
                onClick={() => setShowRuleModal(false)}
                className="text-gray-400 hover:text-gray-600"
              >
                <X className="h-6 w-6" />
              </button>
            </div>
            
            <div className="space-y-4">
              {alertRules.map((rule) => (
                <div key={rule.id} className="border border-gray-200 rounded-lg p-4">
                  <div className="flex items-center justify-between mb-2">
                    <h3 className="font-semibold text-gray-900">{rule.name}</h3>
                    <div className="flex items-center space-x-2">
                      <span className={`px-2 py-1 rounded text-xs font-medium ${
                        rule.severity === 'high' ? 'bg-red-100 text-red-800' :
                        rule.severity === 'medium' ? 'bg-yellow-100 text-yellow-800' :
                        'bg-blue-100 text-blue-800'
                      }`}>
                        {rule.severity}
                      </span>
                      <button
                        className={`toggle-switch ${rule.enabled ? 'enabled' : 'disabled'}`}
                        onClick={() => toggleRule(rule.id)}
                      >
                        <div className="toggle-thumb"></div>
                      </button>
                    </div>
                  </div>
                  <p className="text-sm text-gray-600 mb-2">Condition: {rule.condition}</p>
                  <div className="flex flex-wrap gap-1">
                    {rule.actions.map((action) => (
                      <span key={action} className="px-2 py-1 bg-gray-100 text-gray-700 rounded text-xs">
                        {getActionLabel(action)}
                      </span>
                    ))}
                  </div>
                </div>
              ))}
            </div>
            
            <div className="mt-6 flex justify-end space-x-3">
              <button
                onClick={() => setShowRuleModal(false)}
                className="px-4 py-2 border border-gray-300 rounded-md text-gray-700 hover:bg-gray-50"
              >
                Close
              </button>
              <button
                onClick={() => {/* Add new rule logic */}}
                className="px-4 py-2 bg-blue-600 text-white rounded-md hover:bg-blue-700"
              >
                Add New Rule
              </button>
            </div>
          </div>
        </div>
      </div>
    </div>
  );

  const toggleRule = (ruleId) => {
    setAlertRules(prev => prev.map(rule => 
      rule.id === ruleId ? { ...rule, enabled: !rule.enabled } : rule
    ));
  };

  if (loading) {
    return (
      <div className="flex justify-center items-center h-64">
        <div className="animate-spin rounded-full h-32 w-32 border-b-2 border-blue-500"></div>
      </div>
    );
  }

  return (
    <div className="alerts-center">
      <div className="alerts-header">
        <div className="flex justify-between items-center mb-6">
          <h1 className="text-2xl font-bold text-gray-900">Alerts Center</h1>
          <div className="flex items-center space-x-4">
            {/* Connection Status */}
            <div className={`flex items-center space-x-2 px-3 py-1 rounded-full text-sm ${
              isConnected ? 'bg-green-100 text-green-800' :
              connectionError ? 'bg-red-100 text-red-800' :
              'bg-yellow-100 text-yellow-800'
            }`}>
              {isConnected ? (
                <Wifi className="h-4 w-4" />
              ) : (
                <WifiOff className="h-4 w-4" />
              )}
              <span>{isConnected ? 'Connected' : connectionError ? 'Connection Error' : 'Connecting...'}</span>
            </div>
            
            {/* Alert Rules Button */}
            <button
              onClick={() => setShowRuleModal(true)}
              className="flex items-center space-x-2 px-4 py-2 bg-blue-600 text-white rounded-md hover:bg-blue-700"
            >
              <Settings className="h-4 w-4" />
              <span>Alert Rules</span>
            </button>
          </div>
        </div>
        
        {/* Filters */}
        <div className="filters-section bg-white p-4 rounded-lg shadow-sm mb-6">
          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
            {/* Search */}
            <div className="relative">
              <Search className="h-5 w-5 text-gray-400 absolute left-3 top-1/2 transform -translate-y-1/2" />
              <input
                type="text"
                placeholder="Search alerts..."
                value={searchTerm}
                onChange={(e) => setSearchTerm(e.target.value)}
                className="pl-10 pr-4 py-2 border border-gray-300 rounded-md focus:ring-2 focus:ring-blue-500 focus:border-transparent w-full"
              />
            </div>

            {/* Type Filter */}
            <select
              value={filterType}
              onChange={(e) => setFilterType(e.target.value)}
              className="px-3 py-2 border border-gray-300 rounded-md focus:ring-2 focus:ring-blue-500 focus:border-transparent"
            >
              <option value="all">All Types</option>
              <option value="vital_signs">Vital Signs</option>
              <option value="device">Device</option>
              <option value="medication">Medication</option>
              <option value="system">System</option>
            </select>

            {/* Severity Filter */}
            <select
              value={filterSeverity}
              onChange={(e) => setFilterSeverity(e.target.value)}
              className="px-3 py-2 border border-gray-300 rounded-md focus:ring-2 focus:ring-blue-500 focus:border-transparent"
            >
              <option value="all">All Severities</option>
              <option value="high">High</option>
              <option value="medium">Medium</option>
              <option value="low">Low</option>
            </select>

            {/* Date Filter */}
            <select
              value={dateFilter}
              onChange={(e) => setDateFilter(e.target.value)}
              className="px-3 py-2 border border-gray-300 rounded-md focus:ring-2 focus:ring-blue-500 focus:border-transparent"
            >
              <option value="all">All Time</option>
              <option value="today">Today</option>
              <option value="week">This Week</option>
              <option value="month">This Month</option>
            </select>
          </div>
        </div>

        {/* Alert Summary */}
        <div className="grid grid-cols-1 md:grid-cols-4 gap-4 mb-6">
          <div className="bg-white p-4 rounded-lg shadow-sm border-l-4 border-red-500">
            <div className="flex items-center">
              <AlertTriangle className="h-8 w-8 text-red-500 mr-3" />
              <div>
                <p className="text-sm font-medium text-gray-600">High Priority</p>
                <p className="text-2xl font-bold text-gray-900">
                  {alerts.filter(a => a.severity === 'high').length}
                </p>
              </div>
            </div>
          </div>
          <div className="bg-white p-4 rounded-lg shadow-sm border-l-4 border-yellow-500">
            <div className="flex items-center">
              <Info className="h-8 w-8 text-yellow-500 mr-3" />
              <div>
                <p className="text-sm font-medium text-gray-600">Medium Priority</p>
                <p className="text-2xl font-bold text-gray-900">
                  {alerts.filter(a => a.severity === 'medium').length}
                </p>
              </div>
            </div>
          </div>
          <div className="bg-white p-4 rounded-lg shadow-sm border-l-4 border-blue-500">
            <div className="flex items-center">
              <Bell className="h-8 w-8 text-blue-500 mr-3" />
              <div>
                <p className="text-sm font-medium text-gray-600">Low Priority</p>
                <p className="text-2xl font-bold text-gray-900">
                  {alerts.filter(a => a.severity === 'low').length}
                </p>
              </div>
            </div>
          </div>
          <div className="bg-white p-4 rounded-lg shadow-sm border-l-4 border-gray-500">
            <div className="flex items-center">
              <CheckCircle className="h-8 w-8 text-gray-500 mr-3" />
              <div>
                <p className="text-sm font-medium text-gray-600">Acknowledged</p>
                <p className="text-2xl font-bold text-gray-900">
                  {alerts.filter(a => a.acknowledged).length}
                </p>
              </div>
            </div>
          </div>
        </div>
      </div>

      {/* Alerts List */}
      <div className="alerts-list space-y-4">
        {filteredAlerts.length === 0 ? (
          <div className="text-center py-8">
            <Bell className="h-12 w-12 text-gray-400 mx-auto mb-4" />
            <p className="text-gray-500">No alerts found matching your criteria.</p>
          </div>
        ) : (
          filteredAlerts.map((alert) => (
            <div
              key={alert.id}
              className={`alert-card bg-white p-6 rounded-lg shadow-sm border-l-4 ${getSeverityColor(alert.severity)} ${
                alert.acknowledged ? 'opacity-75' : ''
              }`}
            >
              <div className="flex items-start justify-between">
                <div className="flex items-start space-x-3 flex-1">
                  {getSeverityIcon(alert.severity)}
                  <div className="flex-1">
                    <div className="flex items-center space-x-2 mb-2">
                      <h3 className="text-lg font-semibold text-gray-900">{alert.title}</h3>
                      {alert.acknowledged && (
                        <CheckCircle className="h-5 w-5 text-green-500" />
                      )}
                    </div>
                    <p className="text-gray-700 mb-2">{alert.message}</p>
                    <div className="flex items-center space-x-4 text-sm text-gray-500">
                      {alert.patientName && (
                        <span>Patient: {alert.patientName}</span>
                      )}
                      {alert.nhsNumber && (
                        <span>NHS: {alert.nhsNumber}</span>
                      )}
                      {alert.deviceId && (
                        <span>Device: {alert.deviceId}</span>
                      )}
                      <span>{formatTimestamp(alert.timestamp)}</span>
                    </div>
                  </div>
                </div>
                
                <div className="flex items-center space-x-2 ml-4">
                  {!alert.acknowledged && (
                    <button
                      onClick={() => handleAcknowledge(alert.id)}
                      className="px-3 py-1 bg-green-100 text-green-700 rounded-md hover:bg-green-200 transition-colors text-sm"
                    >
                      Acknowledge
                    </button>
                  )}
                  <button className="p-1 text-gray-400 hover:text-gray-600">
                    <X className="h-5 w-5" />
                  </button>
                </div>
              </div>
              
              {/* Action Buttons */}
              {alert.actions.length > 0 && (
                <div className="mt-4 pt-4 border-t border-gray-200">
                  <div className="flex flex-wrap gap-2">
                    {alert.actions.map((action) => (
                      <button
                        key={action}
                        onClick={() => handleAction(alert.id, action)}
                        className="px-3 py-1 bg-blue-100 text-blue-700 rounded-md hover:bg-blue-200 transition-colors text-sm"
                      >
                        {getActionLabel(action)}
                      </button>
                    ))}
                  </div>
                </div>
              )}
            </div>
          ))
        )}
      </div>
    </div>
  );
};

export default AlertsCenter;
