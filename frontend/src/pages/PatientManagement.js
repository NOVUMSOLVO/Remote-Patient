import React, { useState, useEffect, useContext } from 'react';
import { AuthContext } from '../contexts/AuthContext';
import LoadingSpinner from '../components/shared/LoadingSpinner';

const PatientManagement = () => {
  const { user, hasPermission } = useContext(AuthContext);
  const [patients, setPatients] = useState([]);
  const [loading, setLoading] = useState(true);
  const [searchTerm, setSearchTerm] = useState('');
  const [showAddPatient, setShowAddPatient] = useState(false);
  const [selectedPatient, setSelectedPatient] = useState(null);
  const [formData, setFormData] = useState({
    nhsNumber: '',
    firstName: '',
    lastName: '',
    dateOfBirth: '',
    gender: '',
    phone: '',
    email: '',
    address: '',
    emergencyContact: '',
    medicalConditions: '',
    medications: '',
    allergies: ''
  });

  // Mock patient data - replace with API call
  useEffect(() => {
    setTimeout(() => {
      setPatients([
        {
          id: 1,
          nhsNumber: '123 456 7890',
          firstName: 'John',
          lastName: 'Smith',
          dateOfBirth: '1970-05-15',
          gender: 'Male',
          phone: '020 7123 4567',
          email: 'john.smith@email.com',
          address: '123 Main Street, London, SW1A 1AA',
          emergencyContact: 'Jane Smith - 020 7123 4568',
          status: 'Active',
          lastCheckIn: '2024-01-15 09:30',
          riskLevel: 'Low',
          assignedClinician: 'Dr. Sarah Johnson',
          devices: ['Blood Pressure Monitor', 'Glucose Meter'],
          medicalConditions: ['Hypertension', 'Type 2 Diabetes'],
          recentReadings: {
            bloodPressure: '128/82 mmHg',
            glucose: '6.2 mmol/L',
            weight: '78.5 kg'
          }
        },
        {
          id: 2,
          nhsNumber: '234 567 8901',
          firstName: 'Mary',
          lastName: 'Johnson',
          dateOfBirth: '1965-09-22',
          gender: 'Female',
          phone: '020 7234 5678',
          email: 'mary.johnson@email.com',
          address: '456 Oak Road, Manchester, M1 2AB',
          emergencyContact: 'Tom Johnson - 020 7234 5679',
          status: 'Active',
          lastCheckIn: '2024-01-14 16:45',
          riskLevel: 'Medium',
          assignedClinician: 'Dr. Michael Brown',
          devices: ['Heart Rate Monitor', 'Weight Scale'],
          medicalConditions: ['Heart Disease', 'Obesity'],
          recentReadings: {
            heartRate: '78 bpm',
            weight: '85.2 kg',
            oxygenSaturation: '98%'
          }
        },
        {
          id: 3,
          nhsNumber: '345 678 9012',
          firstName: 'Robert',
          lastName: 'Wilson',
          dateOfBirth: '1982-03-10',
          gender: 'Male',
          phone: '020 7345 6789',
          email: 'robert.wilson@email.com',
          address: '789 Pine Street, Birmingham, B1 3CD',
          emergencyContact: 'Emma Wilson - 020 7345 6790',
          status: 'Monitoring',
          lastCheckIn: '2024-01-15 14:20',
          riskLevel: 'High',
          assignedClinician: 'Dr. Emma Davis',
          devices: ['Blood Pressure Monitor', 'ECG Monitor'],
          medicalConditions: ['Hypertension', 'Arrhythmia'],
          recentReadings: {
            bloodPressure: '145/95 mmHg',
            heartRate: '92 bpm',
            ecg: 'Irregular rhythm detected'
          }
        }
      ]);
      setLoading(false);
    }, 1000);
  }, []);

  const filteredPatients = patients.filter(patient => 
    patient.firstName.toLowerCase().includes(searchTerm.toLowerCase()) ||
    patient.lastName.toLowerCase().includes(searchTerm.toLowerCase()) ||
    patient.nhsNumber.includes(searchTerm)
  );

  const handleAddPatient = (e) => {
    e.preventDefault();
    // Add patient logic here
    console.log('Adding patient:', formData);
    setShowAddPatient(false);
    setFormData({
      nhsNumber: '',
      firstName: '',
      lastName: '',
      dateOfBirth: '',
      gender: '',
      phone: '',
      email: '',
      address: '',
      emergencyContact: '',
      medicalConditions: '',
      medications: '',
      allergies: ''
    });
  };

  const getRiskLevelColor = (level) => {
    switch (level) {
      case 'High': return 'bg-red-100 text-red-800';
      case 'Medium': return 'bg-yellow-100 text-yellow-800';
      case 'Low': return 'bg-green-100 text-green-800';
      default: return 'bg-gray-100 text-gray-800';
    }
  };

  const getStatusColor = (status) => {
    switch (status) {
      case 'Active': return 'bg-green-100 text-green-800';
      case 'Monitoring': return 'bg-blue-100 text-blue-800';
      case 'Inactive': return 'bg-gray-100 text-gray-800';
      default: return 'bg-gray-100 text-gray-800';
    }
  };

  if (loading) {
    return <LoadingSpinner />;
  }

  return (
    <div className="rpm-container">
      <div className="rpm-header">
        <div>
          <h1 className="rpm-page-title">Patient Management</h1>
          <p className="rpm-page-subtitle">
            Monitor and manage patient information and health data
          </p>
        </div>
        {hasPermission('create_patient') && (
          <button
            onClick={() => setShowAddPatient(true)}
            className="rpm-btn rpm-btn-primary"
          >
            <span className="icon-plus" aria-hidden="true">+</span>
            Add Patient
          </button>
        )}
      </div>

      {/* Stats Cards */}
      <div className="grid grid-cols-1 md:grid-cols-4 gap-6 mb-8">
        <div className="rpm-card">
          <div className="rpm-card-body">
            <h3 className="text-sm font-medium text-gray-500">Total Patients</h3>
            <p className="text-2xl font-bold text-nhs-blue">{patients.length}</p>
          </div>
        </div>
        <div className="rpm-card">
          <div className="rpm-card-body">
            <h3 className="text-sm font-medium text-gray-500">Active Monitoring</h3>
            <p className="text-2xl font-bold text-green-600">
              {patients.filter(p => p.status === 'Active' || p.status === 'Monitoring').length}
            </p>
          </div>
        </div>
        <div className="rpm-card">
          <div className="rpm-card-body">
            <h3 className="text-sm font-medium text-gray-500">High Risk</h3>
            <p className="text-2xl font-bold text-red-600">
              {patients.filter(p => p.riskLevel === 'High').length}
            </p>
          </div>
        </div>
        <div className="rpm-card">
          <div className="rpm-card-body">
            <h3 className="text-sm font-medium text-gray-500">Recent Check-ins</h3>
            <p className="text-2xl font-bold text-blue-600">
              {patients.filter(p => {
                const checkIn = new Date(p.lastCheckIn);
                const today = new Date();
                return (today - checkIn) < 24 * 60 * 60 * 1000;
              }).length}
            </p>
          </div>
        </div>
      </div>

      {/* Search and Filter */}
      <div className="rpm-card mb-6">
        <div className="rpm-card-body">
          <div className="flex flex-col sm:flex-row gap-4">
            <div className="flex-1">
              <label htmlFor="search" className="sr-only">Search patients</label>
              <input
                type="text"
                id="search"
                placeholder="Search by name or NHS number..."
                value={searchTerm}
                onChange={(e) => setSearchTerm(e.target.value)}
                className="rpm-input"
              />
            </div>
            <div className="flex gap-2">
              <select className="rpm-select">
                <option value="">All Risk Levels</option>
                <option value="High">High Risk</option>
                <option value="Medium">Medium Risk</option>
                <option value="Low">Low Risk</option>
              </select>
              <select className="rpm-select">
                <option value="">All Statuses</option>
                <option value="Active">Active</option>
                <option value="Monitoring">Monitoring</option>
                <option value="Inactive">Inactive</option>
              </select>
            </div>
          </div>
        </div>
      </div>

      {/* Patients Table */}
      <div className="rpm-card">
        <div className="rpm-card-body p-0">
          <div className="overflow-x-auto">
            <table className="min-w-full divide-y divide-gray-200">
              <thead className="bg-gray-50">
                <tr>
                  <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                    Patient
                  </th>
                  <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                    NHS Number
                  </th>
                  <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                    Status
                  </th>
                  <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                    Risk Level
                  </th>
                  <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                    Assigned Clinician
                  </th>
                  <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                    Last Check-in
                  </th>
                  <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                    Actions
                  </th>
                </tr>
              </thead>
              <tbody className="bg-white divide-y divide-gray-200">
                {filteredPatients.map((patient) => (
                  <tr key={patient.id} className="hover:bg-gray-50">
                    <td className="px-6 py-4 whitespace-nowrap">
                      <div>
                        <div className="text-sm font-medium text-gray-900">
                          {patient.firstName} {patient.lastName}
                        </div>
                        <div className="text-sm text-gray-500">
                          {patient.email}
                        </div>
                      </div>
                    </td>
                    <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-900">
                      {patient.nhsNumber}
                    </td>
                    <td className="px-6 py-4 whitespace-nowrap">
                      <span className={`inline-flex px-2 py-1 text-xs font-semibold rounded-full ${getStatusColor(patient.status)}`}>
                        {patient.status}
                      </span>
                    </td>
                    <td className="px-6 py-4 whitespace-nowrap">
                      <span className={`inline-flex px-2 py-1 text-xs font-semibold rounded-full ${getRiskLevelColor(patient.riskLevel)}`}>
                        {patient.riskLevel}
                      </span>
                    </td>
                    <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-900">
                      {patient.assignedClinician}
                    </td>
                    <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-500">
                      {new Date(patient.lastCheckIn).toLocaleString()}
                    </td>
                    <td className="px-6 py-4 whitespace-nowrap text-sm font-medium">
                      <div className="flex space-x-2">
                        <button
                          onClick={() => setSelectedPatient(patient)}
                          className="text-nhs-blue hover:text-nhs-dark-blue"
                        >
                          View
                        </button>
                        {hasPermission('edit_patient') && (
                          <button className="text-indigo-600 hover:text-indigo-900">
                            Edit
                          </button>
                        )}
                        <button className="text-green-600 hover:text-green-900">
                          Monitor
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

      {/* Add Patient Modal */}
      {showAddPatient && (
        <div className="fixed inset-0 bg-gray-600 bg-opacity-50 overflow-y-auto h-full w-full z-50">
          <div className="relative top-20 mx-auto p-5 border w-11/12 md:w-3/4 lg:w-1/2 shadow-lg rounded-md bg-white">
            <div className="mt-3">
              <h3 className="text-lg font-medium leading-6 text-gray-900 mb-4">
                Add New Patient
              </h3>
              <form onSubmit={handleAddPatient} className="space-y-4">
                <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                  <div>
                    <label className="rpm-label">NHS Number</label>
                    <input
                      type="text"
                      value={formData.nhsNumber}
                      onChange={(e) => setFormData({...formData, nhsNumber: e.target.value})}
                      className="rpm-input"
                      required
                    />
                  </div>
                  <div>
                    <label className="rpm-label">Gender</label>
                    <select
                      value={formData.gender}
                      onChange={(e) => setFormData({...formData, gender: e.target.value})}
                      className="rpm-select"
                      required
                    >
                      <option value="">Select Gender</option>
                      <option value="Male">Male</option>
                      <option value="Female">Female</option>
                      <option value="Other">Other</option>
                    </select>
                  </div>
                  <div>
                    <label className="rpm-label">First Name</label>
                    <input
                      type="text"
                      value={formData.firstName}
                      onChange={(e) => setFormData({...formData, firstName: e.target.value})}
                      className="rpm-input"
                      required
                    />
                  </div>
                  <div>
                    <label className="rpm-label">Last Name</label>
                    <input
                      type="text"
                      value={formData.lastName}
                      onChange={(e) => setFormData({...formData, lastName: e.target.value})}
                      className="rpm-input"
                      required
                    />
                  </div>
                  <div>
                    <label className="rpm-label">Date of Birth</label>
                    <input
                      type="date"
                      value={formData.dateOfBirth}
                      onChange={(e) => setFormData({...formData, dateOfBirth: e.target.value})}
                      className="rpm-input"
                      required
                    />
                  </div>
                  <div>
                    <label className="rpm-label">Phone</label>
                    <input
                      type="tel"
                      value={formData.phone}
                      onChange={(e) => setFormData({...formData, phone: e.target.value})}
                      className="rpm-input"
                      required
                    />
                  </div>
                  <div className="md:col-span-2">
                    <label className="rpm-label">Email</label>
                    <input
                      type="email"
                      value={formData.email}
                      onChange={(e) => setFormData({...formData, email: e.target.value})}
                      className="rpm-input"
                      required
                    />
                  </div>
                  <div className="md:col-span-2">
                    <label className="rpm-label">Address</label>
                    <textarea
                      value={formData.address}
                      onChange={(e) => setFormData({...formData, address: e.target.value})}
                      className="rpm-textarea"
                      rows="2"
                      required
                    />
                  </div>
                  <div className="md:col-span-2">
                    <label className="rpm-label">Emergency Contact</label>
                    <input
                      type="text"
                      value={formData.emergencyContact}
                      onChange={(e) => setFormData({...formData, emergencyContact: e.target.value})}
                      className="rpm-input"
                      placeholder="Name - Phone Number"
                      required
                    />
                  </div>
                  <div className="md:col-span-2">
                    <label className="rpm-label">Medical Conditions</label>
                    <textarea
                      value={formData.medicalConditions}
                      onChange={(e) => setFormData({...formData, medicalConditions: e.target.value})}
                      className="rpm-textarea"
                      rows="2"
                      placeholder="List any existing medical conditions"
                    />
                  </div>
                </div>
                <div className="flex justify-end space-x-3 pt-4">
                  <button
                    type="button"
                    onClick={() => setShowAddPatient(false)}
                    className="rpm-btn rpm-btn-secondary"
                  >
                    Cancel
                  </button>
                  <button
                    type="submit"
                    className="rpm-btn rpm-btn-primary"
                  >
                    Add Patient
                  </button>
                </div>
              </form>
            </div>
          </div>
        </div>
      )}

      {/* Patient Details Modal */}
      {selectedPatient && (
        <div className="fixed inset-0 bg-gray-600 bg-opacity-50 overflow-y-auto h-full w-full z-50">
          <div className="relative top-10 mx-auto p-5 border w-11/12 md:w-4/5 lg:w-3/4 shadow-lg rounded-md bg-white">
            <div className="mt-3">
              <div className="flex justify-between items-center mb-4">
                <h3 className="text-lg font-medium leading-6 text-gray-900">
                  {selectedPatient.firstName} {selectedPatient.lastName} - Patient Details
                </h3>
                <button
                  onClick={() => setSelectedPatient(null)}
                  className="text-gray-400 hover:text-gray-600"
                >
                  <span className="sr-only">Close</span>
                  <svg className="h-6 w-6" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M6 18L18 6M6 6l12 12" />
                  </svg>
                </button>
              </div>
              
              <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
                {/* Patient Information */}
                <div className="space-y-4">
                  <div className="rpm-card">
                    <div className="rpm-card-header">
                      <h4 className="text-lg font-medium">Patient Information</h4>
                    </div>
                    <div className="rpm-card-body space-y-3">
                      <div className="grid grid-cols-2 gap-4">
                        <div>
                          <p className="text-sm font-medium text-gray-500">NHS Number</p>
                          <p className="text-sm text-gray-900">{selectedPatient.nhsNumber}</p>
                        </div>
                        <div>
                          <p className="text-sm font-medium text-gray-500">Date of Birth</p>
                          <p className="text-sm text-gray-900">{selectedPatient.dateOfBirth}</p>
                        </div>
                        <div>
                          <p className="text-sm font-medium text-gray-500">Gender</p>
                          <p className="text-sm text-gray-900">{selectedPatient.gender}</p>
                        </div>
                        <div>
                          <p className="text-sm font-medium text-gray-500">Phone</p>
                          <p className="text-sm text-gray-900">{selectedPatient.phone}</p>
                        </div>
                      </div>
                      <div>
                        <p className="text-sm font-medium text-gray-500">Email</p>
                        <p className="text-sm text-gray-900">{selectedPatient.email}</p>
                      </div>
                      <div>
                        <p className="text-sm font-medium text-gray-500">Address</p>
                        <p className="text-sm text-gray-900">{selectedPatient.address}</p>
                      </div>
                      <div>
                        <p className="text-sm font-medium text-gray-500">Emergency Contact</p>
                        <p className="text-sm text-gray-900">{selectedPatient.emergencyContact}</p>
                      </div>
                    </div>
                  </div>

                  {/* Medical Information */}
                  <div className="rpm-card">
                    <div className="rpm-card-header">
                      <h4 className="text-lg font-medium">Medical Information</h4>
                    </div>
                    <div className="rpm-card-body space-y-3">
                      <div>
                        <p className="text-sm font-medium text-gray-500">Medical Conditions</p>
                        <div className="flex flex-wrap gap-2 mt-1">
                          {selectedPatient.medicalConditions.map((condition, index) => (
                            <span key={index} className="inline-flex px-2 py-1 text-xs font-semibold rounded-full bg-blue-100 text-blue-800">
                              {condition}
                            </span>
                          ))}
                        </div>
                      </div>
                      <div>
                        <p className="text-sm font-medium text-gray-500">Assigned Devices</p>
                        <div className="flex flex-wrap gap-2 mt-1">
                          {selectedPatient.devices.map((device, index) => (
                            <span key={index} className="inline-flex px-2 py-1 text-xs font-semibold rounded-full bg-green-100 text-green-800">
                              {device}
                            </span>
                          ))}
                        </div>
                      </div>
                      <div>
                        <p className="text-sm font-medium text-gray-500">Assigned Clinician</p>
                        <p className="text-sm text-gray-900">{selectedPatient.assignedClinician}</p>
                      </div>
                    </div>
                  </div>
                </div>

                {/* Recent Readings and Status */}
                <div className="space-y-4">
                  <div className="rpm-card">
                    <div className="rpm-card-header">
                      <h4 className="text-lg font-medium">Current Status</h4>
                    </div>
                    <div className="rpm-card-body space-y-3">
                      <div className="grid grid-cols-2 gap-4">
                        <div>
                          <p className="text-sm font-medium text-gray-500">Status</p>
                          <span className={`inline-flex px-2 py-1 text-xs font-semibold rounded-full ${getStatusColor(selectedPatient.status)}`}>
                            {selectedPatient.status}
                          </span>
                        </div>
                        <div>
                          <p className="text-sm font-medium text-gray-500">Risk Level</p>
                          <span className={`inline-flex px-2 py-1 text-xs font-semibold rounded-full ${getRiskLevelColor(selectedPatient.riskLevel)}`}>
                            {selectedPatient.riskLevel}
                          </span>
                        </div>
                      </div>
                      <div>
                        <p className="text-sm font-medium text-gray-500">Last Check-in</p>
                        <p className="text-sm text-gray-900">{new Date(selectedPatient.lastCheckIn).toLocaleString()}</p>
                      </div>
                    </div>
                  </div>

                  <div className="rpm-card">
                    <div className="rpm-card-header">
                      <h4 className="text-lg font-medium">Recent Readings</h4>
                    </div>
                    <div className="rpm-card-body space-y-3">
                      {Object.entries(selectedPatient.recentReadings).map(([key, value]) => (
                        <div key={key} className="flex justify-between">
                          <span className="text-sm font-medium text-gray-500 capitalize">
                            {key.replace(/([A-Z])/g, ' $1').trim()}
                          </span>
                          <span className="text-sm text-gray-900">{value}</span>
                        </div>
                      ))}
                    </div>
                  </div>

                  <div className="flex space-x-3">
                    <button className="rpm-btn rpm-btn-primary flex-1">
                      View Full History
                    </button>
                    <button className="rpm-btn rpm-btn-secondary flex-1">
                      Update Status
                    </button>
                  </div>
                </div>
              </div>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};

export default PatientManagement;
