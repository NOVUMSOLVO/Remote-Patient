import React, { useState, useEffect, useContext } from 'react';
import { AuthContext } from '../contexts/AuthContext';
import LoadingSpinner from '../components/shared/LoadingSpinner';

const DeviceManagement = () => {
  const { user, hasPermission } = useContext(AuthContext);
  const [devices, setDevices] = useState([]);
  const [loading, setLoading] = useState(true);
  const [searchTerm, setSearchTerm] = useState('');
  const [showAddDevice, setShowAddDevice] = useState(false);
  const [selectedDevice, setSelectedDevice] = useState(null);
  const [formData, setFormData] = useState({
    deviceId: '',
    deviceType: '',
    manufacturer: '',
    model: '',
    serialNumber: '',
    assignedPatient: '',
    location: '',
    calibrationDate: '',
    nextCalibration: '',
    batteryLevel: '',
    firmwareVersion: ''
  });

  // Mock device data - replace with API call
  useEffect(() => {
    setTimeout(() => {
      setDevices([
        {
          id: 1,
          deviceId: 'BP001',
          deviceType: 'Blood Pressure Monitor',
          manufacturer: 'Omron',
          model: 'HEM-7156T',
          serialNumber: 'OM123456789',
          status: 'Active',
          connectionStatus: 'Connected',
          batteryLevel: 85,
          lastReading: '2024-01-15 09:30',
          assignedPatient: 'John Smith (123 456 7890)',
          location: 'Home',
          calibrationDate: '2024-01-01',
          nextCalibration: '2024-07-01',
          firmwareVersion: '2.1.0',
          readings: 156,
          alerts: 2,
          lastSync: '2024-01-15 09:35'
        },
        {
          id: 2,
          deviceId: 'GM002',
          deviceType: 'Glucose Meter',
          manufacturer: 'Accu-Chek',
          model: 'Guide',
          serialNumber: 'AC987654321',
          status: 'Active',
          connectionStatus: 'Connected',
          batteryLevel: 92,
          lastReading: '2024-01-15 08:45',
          assignedPatient: 'John Smith (123 456 7890)',
          location: 'Home',
          calibrationDate: '2024-01-15',
          nextCalibration: '2024-02-15',
          firmwareVersion: '1.5.2',
          readings: 89,
          alerts: 0,
          lastSync: '2024-01-15 08:50'
        },
        {
          id: 3,
          deviceId: 'HR003',
          deviceType: 'Heart Rate Monitor',
          manufacturer: 'Polar',
          model: 'H10',
          serialNumber: 'PL456789123',
          status: 'Active',
          connectionStatus: 'Disconnected',
          batteryLevel: 45,
          lastReading: '2024-01-14 20:15',
          assignedPatient: 'Mary Johnson (234 567 8901)',
          location: 'Home',
          calibrationDate: '2023-12-01',
          nextCalibration: '2024-06-01',
          firmwareVersion: '3.2.1',
          readings: 234,
          alerts: 1,
          lastSync: '2024-01-14 20:20'
        },
        {
          id: 4,
          deviceId: 'WS004',
          deviceType: 'Weight Scale',
          manufacturer: 'Withings',
          model: 'Body+',
          serialNumber: 'WT789123456',
          status: 'Active',
          connectionStatus: 'Connected',
          batteryLevel: 78,
          lastReading: '2024-01-15 07:00',
          assignedPatient: 'Mary Johnson (234 567 8901)',
          location: 'Home',
          calibrationDate: '2024-01-10',
          nextCalibration: '2024-07-10',
          firmwareVersion: '4.1.0',
          readings: 67,
          alerts: 0,
          lastSync: '2024-01-15 07:05'
        },
        {
          id: 5,
          deviceId: 'ECG005',
          deviceType: 'ECG Monitor',
          manufacturer: 'AliveCor',
          model: 'KardiaMobile',
          serialNumber: 'AC123789456',
          status: 'Maintenance',
          connectionStatus: 'Disconnected',
          batteryLevel: 12,
          lastReading: '2024-01-13 16:30',
          assignedPatient: 'Robert Wilson (345 678 9012)',
          location: 'Home',
          calibrationDate: '2023-11-15',
          nextCalibration: '2024-05-15',
          firmwareVersion: '2.8.3',
          readings: 45,
          alerts: 3,
          lastSync: '2024-01-13 16:35'
        }
      ]);
      setLoading(false);
    }, 1000);
  }, []);

  const filteredDevices = devices.filter(device => 
    device.deviceId.toLowerCase().includes(searchTerm.toLowerCase()) ||
    device.deviceType.toLowerCase().includes(searchTerm.toLowerCase()) ||
    device.manufacturer.toLowerCase().includes(searchTerm.toLowerCase()) ||
    (device.assignedPatient && device.assignedPatient.toLowerCase().includes(searchTerm.toLowerCase()))
  );

  const handleAddDevice = (e) => {
    e.preventDefault();
    // Add device logic here
    console.log('Adding device:', formData);
    setShowAddDevice(false);
    setFormData({
      deviceId: '',
      deviceType: '',
      manufacturer: '',
      model: '',
      serialNumber: '',
      assignedPatient: '',
      location: '',
      calibrationDate: '',
      nextCalibration: '',
      batteryLevel: '',
      firmwareVersion: ''
    });
  };

  const getStatusColor = (status) => {
    switch (status) {
      case 'Active': return 'bg-green-100 text-green-800';
      case 'Maintenance': return 'bg-yellow-100 text-yellow-800';
      case 'Inactive': return 'bg-gray-100 text-gray-800';
      case 'Error': return 'bg-red-100 text-red-800';
      default: return 'bg-gray-100 text-gray-800';
    }
  };

  const getConnectionColor = (status) => {
    switch (status) {
      case 'Connected': return 'bg-green-100 text-green-800';
      case 'Disconnected': return 'bg-red-100 text-red-800';
      case 'Syncing': return 'bg-blue-100 text-blue-800';
      default: return 'bg-gray-100 text-gray-800';
    }
  };

  const getBatteryColor = (level) => {
    if (level > 70) return 'text-green-600';
    if (level > 30) return 'text-yellow-600';
    return 'text-red-600';
  };

  if (loading) {
    return <LoadingSpinner />;
  }

  return (
    <div className="rpm-container">
      <div className="rpm-header">
        <div>
          <h1 className="rpm-page-title">Device Management</h1>
          <p className="rpm-page-subtitle">
            Monitor and manage remote patient monitoring devices
          </p>
        </div>
        {hasPermission('create_device') && (
          <button
            onClick={() => setShowAddDevice(true)}
            className="rpm-btn rpm-btn-primary"
          >
            <span className="icon-plus" aria-hidden="true">+</span>
            Add Device
          </button>
        )}
      </div>

      {/* Stats Cards */}
      <div className="grid grid-cols-1 md:grid-cols-5 gap-6 mb-8">
        <div className="rpm-card">
          <div className="rpm-card-body">
            <h3 className="text-sm font-medium text-gray-500">Total Devices</h3>
            <p className="text-2xl font-bold text-nhs-blue">{devices.length}</p>
          </div>
        </div>
        <div className="rpm-card">
          <div className="rpm-card-body">
            <h3 className="text-sm font-medium text-gray-500">Active</h3>
            <p className="text-2xl font-bold text-green-600">
              {devices.filter(d => d.status === 'Active').length}
            </p>
          </div>
        </div>
        <div className="rpm-card">
          <div className="rpm-card-body">
            <h3 className="text-sm font-medium text-gray-500">Connected</h3>
            <p className="text-2xl font-bold text-blue-600">
              {devices.filter(d => d.connectionStatus === 'Connected').length}
            </p>
          </div>
        </div>
        <div className="rpm-card">
          <div className="rpm-card-body">
            <h3 className="text-sm font-medium text-gray-500">Low Battery</h3>
            <p className="text-2xl font-bold text-red-600">
              {devices.filter(d => d.batteryLevel < 30).length}
            </p>
          </div>
        </div>
        <div className="rpm-card">
          <div className="rpm-card-body">
            <h3 className="text-sm font-medium text-gray-500">Alerts</h3>
            <p className="text-2xl font-bold text-orange-600">
              {devices.reduce((sum, d) => sum + d.alerts, 0)}
            </p>
          </div>
        </div>
      </div>

      {/* Search and Filter */}
      <div className="rpm-card mb-6">
        <div className="rpm-card-body">
          <div className="flex flex-col sm:flex-row gap-4">
            <div className="flex-1">
              <label htmlFor="search" className="sr-only">Search devices</label>
              <input
                type="text"
                id="search"
                placeholder="Search by device ID, type, manufacturer, or patient..."
                value={searchTerm}
                onChange={(e) => setSearchTerm(e.target.value)}
                className="rpm-input"
              />
            </div>
            <div className="flex gap-2">
              <select className="rpm-select">
                <option value="">All Types</option>
                <option value="Blood Pressure Monitor">Blood Pressure Monitor</option>
                <option value="Glucose Meter">Glucose Meter</option>
                <option value="Heart Rate Monitor">Heart Rate Monitor</option>
                <option value="Weight Scale">Weight Scale</option>
                <option value="ECG Monitor">ECG Monitor</option>
              </select>
              <select className="rpm-select">
                <option value="">All Statuses</option>
                <option value="Active">Active</option>
                <option value="Maintenance">Maintenance</option>
                <option value="Inactive">Inactive</option>
                <option value="Error">Error</option>
              </select>
            </div>
          </div>
        </div>
      </div>

      {/* Devices Table */}
      <div className="rpm-card">
        <div className="rpm-card-body p-0">
          <div className="overflow-x-auto">
            <table className="min-w-full divide-y divide-gray-200">
              <thead className="bg-gray-50">
                <tr>
                  <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                    Device
                  </th>
                  <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                    Status
                  </th>
                  <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                    Connection
                  </th>
                  <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                    Battery
                  </th>
                  <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                    Assigned Patient
                  </th>
                  <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                    Last Reading
                  </th>
                  <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                    Actions
                  </th>
                </tr>
              </thead>
              <tbody className="bg-white divide-y divide-gray-200">
                {filteredDevices.map((device) => (
                  <tr key={device.id} className="hover:bg-gray-50">
                    <td className="px-6 py-4 whitespace-nowrap">
                      <div>
                        <div className="text-sm font-medium text-gray-900">
                          {device.deviceId} - {device.deviceType}
                        </div>
                        <div className="text-sm text-gray-500">
                          {device.manufacturer} {device.model}
                        </div>
                      </div>
                    </td>
                    <td className="px-6 py-4 whitespace-nowrap">
                      <span className={`inline-flex px-2 py-1 text-xs font-semibold rounded-full ${getStatusColor(device.status)}`}>
                        {device.status}
                      </span>
                    </td>
                    <td className="px-6 py-4 whitespace-nowrap">
                      <span className={`inline-flex px-2 py-1 text-xs font-semibold rounded-full ${getConnectionColor(device.connectionStatus)}`}>
                        {device.connectionStatus}
                      </span>
                    </td>
                    <td className="px-6 py-4 whitespace-nowrap">
                      <div className="flex items-center">
                        <span className={`text-sm font-medium ${getBatteryColor(device.batteryLevel)}`}>
                          {device.batteryLevel}%
                        </span>
                        <div className="ml-2 w-16 bg-gray-200 rounded-full h-2">
                          <div 
                            className={`h-2 rounded-full ${device.batteryLevel > 70 ? 'bg-green-500' : device.batteryLevel > 30 ? 'bg-yellow-500' : 'bg-red-500'}`}
                            style={{ width: `${device.batteryLevel}%` }}
                          ></div>
                        </div>
                      </div>
                    </td>
                    <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-900">
                      {device.assignedPatient || 'Unassigned'}
                    </td>
                    <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-500">
                      {new Date(device.lastReading).toLocaleString()}
                    </td>
                    <td className="px-6 py-4 whitespace-nowrap text-sm font-medium">
                      <div className="flex space-x-2">
                        <button
                          onClick={() => setSelectedDevice(device)}
                          className="text-nhs-blue hover:text-nhs-dark-blue"
                        >
                          View
                        </button>
                        {hasPermission('edit_device') && (
                          <button className="text-indigo-600 hover:text-indigo-900">
                            Edit
                          </button>
                        )}
                        <button className="text-green-600 hover:text-green-900">
                          Sync
                        </button>
                      </div>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      </div>

      {/* Add Device Modal */}
      {showAddDevice && (
        <div className="fixed inset-0 bg-gray-600 bg-opacity-50 overflow-y-auto h-full w-full z-50">
          <div className="relative top-20 mx-auto p-5 border w-11/12 md:w-3/4 lg:w-1/2 shadow-lg rounded-md bg-white">
            <div className="mt-3">
              <h3 className="text-lg font-medium leading-6 text-gray-900 mb-4">
                Add New Device
              </h3>
              <form onSubmit={handleAddDevice} className="space-y-4">
                <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                  <div>
                    <label className="rpm-label">Device ID</label>
                    <input
                      type="text"
                      value={formData.deviceId}
                      onChange={(e) => setFormData({...formData, deviceId: e.target.value})}
                      className="rpm-input"
                      required
                    />
                  </div>
                  <div>
                    <label className="rpm-label">Device Type</label>
                    <select
                      value={formData.deviceType}
                      onChange={(e) => setFormData({...formData, deviceType: e.target.value})}
                      className="rpm-select"
                      required
                    >
                      <option value="">Select Device Type</option>
                      <option value="Blood Pressure Monitor">Blood Pressure Monitor</option>
                      <option value="Glucose Meter">Glucose Meter</option>
                      <option value="Heart Rate Monitor">Heart Rate Monitor</option>
                      <option value="Weight Scale">Weight Scale</option>
                      <option value="ECG Monitor">ECG Monitor</option>
                      <option value="Pulse Oximeter">Pulse Oximeter</option>
                      <option value="Thermometer">Thermometer</option>
                    </select>
                  </div>
                  <div>
                    <label className="rpm-label">Manufacturer</label>
                    <input
                      type="text"
                      value={formData.manufacturer}
                      onChange={(e) => setFormData({...formData, manufacturer: e.target.value})}
                      className="rpm-input"
                      required
                    />
                  </div>
                  <div>
                    <label className="rpm-label">Model</label>
                    <input
                      type="text"
                      value={formData.model}
                      onChange={(e) => setFormData({...formData, model: e.target.value})}
                      className="rpm-input"
                      required
                    />
                  </div>
                  <div>
                    <label className="rpm-label">Serial Number</label>
                    <input
                      type="text"
                      value={formData.serialNumber}
                      onChange={(e) => setFormData({...formData, serialNumber: e.target.value})}
                      className="rpm-input"
                      required
                    />
                  </div>
                  <div>
                    <label className="rpm-label">Firmware Version</label>
                    <input
                      type="text"
                      value={formData.firmwareVersion}
                      onChange={(e) => setFormData({...formData, firmwareVersion: e.target.value})}
                      className="rpm-input"
                    />
                  </div>
                  <div>
                    <label className="rpm-label">Assigned Patient (Optional)</label>
                    <select
                      value={formData.assignedPatient}
                      onChange={(e) => setFormData({...formData, assignedPatient: e.target.value})}
                      className="rpm-select"
                    >
                      <option value="">Select Patient</option>
                      <option value="John Smith (123 456 7890)">John Smith (123 456 7890)</option>
                      <option value="Mary Johnson (234 567 8901)">Mary Johnson (234 567 8901)</option>
                      <option value="Robert Wilson (345 678 9012)">Robert Wilson (345 678 9012)</option>
                    </select>
                  </div>
                  <div>
                    <label className="rpm-label">Location</label>
                    <input
                      type="text"
                      value={formData.location}
                      onChange={(e) => setFormData({...formData, location: e.target.value})}
                      className="rpm-input"
                      placeholder="e.g., Home, Ward A, Room 101"
                    />
                  </div>
                  <div>
                    <label className="rpm-label">Calibration Date</label>
                    <input
                      type="date"
                      value={formData.calibrationDate}
                      onChange={(e) => setFormData({...formData, calibrationDate: e.target.value})}
                      className="rpm-input"
                    />
                  </div>
                  <div>
                    <label className="rpm-label">Next Calibration</label>
                    <input
                      type="date"
                      value={formData.nextCalibration}
                      onChange={(e) => setFormData({...formData, nextCalibration: e.target.value})}
                      className="rpm-input"
                    />
                  </div>
                </div>
                <div className="flex justify-end space-x-3 pt-4">
                  <button
                    type="button"
                    onClick={() => setShowAddDevice(false)}
                    className="rpm-btn rpm-btn-secondary"
                  >
                    Cancel
                  </button>
                  <button
                    type="submit"
                    className="rpm-btn rpm-btn-primary"
                  >
                    Add Device
                  </button>
                </div>
              </form>
            </div>
          </div>
        </div>
      )}

      {/* Device Details Modal */}
      {selectedDevice && (
        <div className="fixed inset-0 bg-gray-600 bg-opacity-50 overflow-y-auto h-full w-full z-50">
          <div className="relative top-10 mx-auto p-5 border w-11/12 md:w-4/5 lg:w-3/4 shadow-lg rounded-md bg-white">
            <div className="mt-3">
              <div className="flex justify-between items-center mb-4">
                <h3 className="text-lg font-medium leading-6 text-gray-900">
                  {selectedDevice.deviceId} - Device Details
                </h3>
                <button
                  onClick={() => setSelectedDevice(null)}
                  className="text-gray-400 hover:text-gray-600"
                >
                  <span className="sr-only">Close</span>
                  <svg className="h-6 w-6" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M6 18L18 6M6 6l12 12" />
                  </svg>
                </button>
              </div>
              
              <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
                {/* Device Information */}
                <div className="space-y-4">
                  <div className="rpm-card">
                    <div className="rpm-card-header">
                      <h4 className="text-lg font-medium">Device Information</h4>
                    </div>
                    <div className="rpm-card-body space-y-3">
                      <div className="grid grid-cols-2 gap-4">
                        <div>
                          <p className="text-sm font-medium text-gray-500">Device ID</p>
                          <p className="text-sm text-gray-900">{selectedDevice.deviceId}</p>
                        </div>
                        <div>
                          <p className="text-sm font-medium text-gray-500">Type</p>
                          <p className="text-sm text-gray-900">{selectedDevice.deviceType}</p>
                        </div>
                        <div>
                          <p className="text-sm font-medium text-gray-500">Manufacturer</p>
                          <p className="text-sm text-gray-900">{selectedDevice.manufacturer}</p>
                        </div>
                        <div>
                          <p className="text-sm font-medium text-gray-500">Model</p>
                          <p className="text-sm text-gray-900">{selectedDevice.model}</p>
                        </div>
                      </div>
                      <div>
                        <p className="text-sm font-medium text-gray-500">Serial Number</p>
                        <p className="text-sm text-gray-900">{selectedDevice.serialNumber}</p>
                      </div>
                      <div>
                        <p className="text-sm font-medium text-gray-500">Firmware Version</p>
                        <p className="text-sm text-gray-900">{selectedDevice.firmwareVersion}</p>
                      </div>
                      <div>
                        <p className="text-sm font-medium text-gray-500">Location</p>
                        <p className="text-sm text-gray-900">{selectedDevice.location}</p>
                      </div>
                    </div>
                  </div>

                  {/* Assignment Information */}
                  <div className="rpm-card">
                    <div className="rpm-card-header">
                      <h4 className="text-lg font-medium">Assignment & Calibration</h4>
                    </div>
                    <div className="rpm-card-body space-y-3">
                      <div>
                        <p className="text-sm font-medium text-gray-500">Assigned Patient</p>
                        <p className="text-sm text-gray-900">{selectedDevice.assignedPatient || 'Unassigned'}</p>
                      </div>
                      <div className="grid grid-cols-2 gap-4">
                        <div>
                          <p className="text-sm font-medium text-gray-500">Calibration Date</p>
                          <p className="text-sm text-gray-900">{selectedDevice.calibrationDate}</p>
                        </div>
                        <div>
                          <p className="text-sm font-medium text-gray-500">Next Calibration</p>
                          <p className="text-sm text-gray-900">{selectedDevice.nextCalibration}</p>
                        </div>
                      </div>
                    </div>
                  </div>
                </div>

                {/* Status and Performance */}
                <div className="space-y-4">
                  <div className="rpm-card">
                    <div className="rpm-card-header">
                      <h4 className="text-lg font-medium">Current Status</h4>
                    </div>
                    <div className="rpm-card-body space-y-3">
                      <div className="grid grid-cols-2 gap-4">
                        <div>
                          <p className="text-sm font-medium text-gray-500">Status</p>
                          <span className={`inline-flex px-2 py-1 text-xs font-semibold rounded-full ${getStatusColor(selectedDevice.status)}`}>
                            {selectedDevice.status}
                          </span>
                        </div>
                        <div>
                          <p className="text-sm font-medium text-gray-500">Connection</p>
                          <span className={`inline-flex px-2 py-1 text-xs font-semibold rounded-full ${getConnectionColor(selectedDevice.connectionStatus)}`}>
                            {selectedDevice.connectionStatus}
                          </span>
                        </div>
                      </div>
                      <div>
                        <p className="text-sm font-medium text-gray-500">Battery Level</p>
                        <div className="flex items-center mt-1">
                          <span className={`text-sm font-medium ${getBatteryColor(selectedDevice.batteryLevel)}`}>
                            {selectedDevice.batteryLevel}%
                          </span>
                          <div className="ml-2 w-32 bg-gray-200 rounded-full h-2">
                            <div 
                              className={`h-2 rounded-full ${selectedDevice.batteryLevel > 70 ? 'bg-green-500' : selectedDevice.batteryLevel > 30 ? 'bg-yellow-500' : 'bg-red-500'}`}
                              style={{ width: `${selectedDevice.batteryLevel}%` }}
                            ></div>
                          </div>
                        </div>
                      </div>
                      <div className="grid grid-cols-2 gap-4">
                        <div>
                          <p className="text-sm font-medium text-gray-500">Last Reading</p>
                          <p className="text-sm text-gray-900">{new Date(selectedDevice.lastReading).toLocaleString()}</p>
                        </div>
                        <div>
                          <p className="text-sm font-medium text-gray-500">Last Sync</p>
                          <p className="text-sm text-gray-900">{new Date(selectedDevice.lastSync).toLocaleString()}</p>
                        </div>
                      </div>
                    </div>
                  </div>

                  <div className="rpm-card">
                    <div className="rpm-card-header">
                      <h4 className="text-lg font-medium">Performance Statistics</h4>
                    </div>
                    <div className="rpm-card-body space-y-3">
                      <div className="grid grid-cols-2 gap-4">
                        <div>
                          <p className="text-sm font-medium text-gray-500">Total Readings</p>
                          <p className="text-sm text-gray-900">{selectedDevice.readings}</p>
                        </div>
                        <div>
                          <p className="text-sm font-medium text-gray-500">Active Alerts</p>
                          <p className="text-sm text-gray-900">{selectedDevice.alerts}</p>
                        </div>
                      </div>
                    </div>
                  </div>

                  <div className="flex space-x-3">
                    <button className="rpm-btn rpm-btn-primary flex-1">
                      View Readings History
                    </button>
                    <button className="rpm-btn rpm-btn-secondary flex-1">
                      Run Diagnostics
                    </button>
                  </div>
                  
                  {selectedDevice.alerts > 0 && (
                    <div className="rpm-card border-l-4 border-orange-400">
                      <div className="rpm-card-body">
                        <div className="flex">
                          <div className="flex-shrink-0">
                            <svg className="h-5 w-5 text-orange-400" viewBox="0 0 20 20" fill="currentColor">
                              <path fillRule="evenodd" d="M8.257 3.099c.765-1.36 2.722-1.36 3.486 0l5.58 9.92c.75 1.334-.213 2.98-1.742 2.98H4.42c-1.53 0-2.493-1.646-1.743-2.98l5.58-9.92zM11 13a1 1 0 11-2 0 1 1 0 012 0zm-1-8a1 1 0 00-1 1v3a1 1 0 002 0V6a1 1 0 00-1-1z" clipRule="evenodd" />
                            </svg>
                          </div>
                          <div className="ml-3">
                            <h3 className="text-sm font-medium text-orange-800">
                              Device Alerts ({selectedDevice.alerts})
                            </h3>
                            <div className="mt-2 text-sm text-orange-700">
                              <p>This device has active alerts that require attention.</p>
                            </div>
                          </div>
                        </div>
                      </div>
                    </div>
                  )}
                </div>
              </div>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};

export default DeviceManagement;
