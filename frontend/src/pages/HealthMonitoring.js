import React, { useState, useEffect } from 'react';
import { Line, Bar, Pie } from 'react-chartjs-2';
import {
  Chart as ChartJS,
  CategoryScale,
  LinearScale,
  PointElement,
  LineElement,
  BarElement,
  Title,
  Tooltip,
  Legend,
  ArcElement,
} from 'chart.js';

// Register Chart.js components
ChartJS.register(
  CategoryScale,
  LinearScale,
  PointElement,
  LineElement,
  BarElement,
  Title,
  Tooltip,
  Legend,
  ArcElement
);

const HealthMonitoring = () => {
  const [selectedPatient, setSelectedPatient] = useState('');
  const [timeRange, setTimeRange] = useState('24h');
  const [selectedMetrics, setSelectedMetrics] = useState(['heart_rate', 'blood_pressure']);
  const [realTimeData, setRealTimeData] = useState({});
  const [isLoading, setIsLoading] = useState(false);

  // Mock data for demonstration
  const [patients] = useState([
    { id: 1, name: 'John Smith', nhsNumber: 'NHS123456789' },
    { id: 2, name: 'Sarah Johnson', nhsNumber: 'NHS987654321' },
    { id: 3, name: 'Michael Brown', nhsNumber: 'NHS456789123' },
  ]);

  const metrics = [
    { id: 'heart_rate', name: 'Heart Rate', unit: 'bpm', color: '#d32f2f', normalRange: '60-100' },
    { id: 'blood_pressure', name: 'Blood Pressure', unit: 'mmHg', color: '#1976d2', normalRange: '120/80' },
    { id: 'temperature', name: 'Temperature', unit: '°C', color: '#388e3c', normalRange: '36.1-37.2' },
    { id: 'oxygen_saturation', name: 'Oxygen Saturation', unit: '%', color: '#7b1fa2', normalRange: '95-100' },
    { id: 'blood_glucose', name: 'Blood Glucose', unit: 'mmol/L', color: '#f57c00', normalRange: '4.0-7.8' },
    { id: 'weight', name: 'Weight', unit: 'kg', color: '#00796b', normalRange: 'varies' },
  ];

  // Generate mock time series data
  const generateTimeSeriesData = (metric, hours = 24) => {
    const data = [];
    const labels = [];
    const now = new Date();
    
    for (let i = hours; i >= 0; i--) {
      const time = new Date(now.getTime() - i * 60 * 60 * 1000);
      labels.push(time.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' }));
      
      let value;
      switch (metric) {
        case 'heart_rate':
          value = 70 + Math.random() * 30 + Math.sin(i * 0.1) * 10;
          break;
        case 'blood_pressure':
          value = 120 + Math.random() * 20 + Math.sin(i * 0.1) * 5;
          break;
        case 'temperature':
          value = 36.5 + Math.random() * 1 + Math.sin(i * 0.1) * 0.3;
          break;
        case 'oxygen_saturation':
          value = 96 + Math.random() * 3;
          break;
        case 'blood_glucose':
          value = 5.5 + Math.random() * 2 + Math.sin(i * 0.1) * 1;
          break;
        case 'weight':
          value = 70 + Math.random() * 2;
          break;
        default:
          value = Math.random() * 100;
      }
      data.push(Math.round(value * 10) / 10);
    }
    
    return { labels, data };
  };

  // Chart configurations
  const lineChartOptions = {
    responsive: true,
    maintainAspectRatio: false,
    plugins: {
      legend: {
        position: 'top',
      },
      title: {
        display: true,
        text: 'Vital Signs Trends',
      },
    },
    scales: {
      y: {
        beginAtZero: false,
      },
    },
  };

  const createLineChartData = () => {
    const timeData = generateTimeSeriesData('heart_rate', timeRange === '24h' ? 24 : timeRange === '7d' ? 168 : 720);
    
    return {
      labels: timeData.labels,
      datasets: selectedMetrics.map(metricId => {
        const metric = metrics.find(m => m.id === metricId);
        const data = generateTimeSeriesData(metricId, timeRange === '24h' ? 24 : timeRange === '7d' ? 168 : 720);
        
        return {
          label: metric.name,
          data: data.data,
          borderColor: metric.color,
          backgroundColor: metric.color + '20',
          tension: 0.1,
        };
      }),
    };
  };

  // Alert status chart
  const alertStatusData = {
    labels: ['Normal', 'Warning', 'Critical'],
    datasets: [
      {
        data: [85, 12, 3],
        backgroundColor: ['#4caf50', '#ff9800', '#f44336'],
        borderWidth: 2,
      },
    ],
  };

  const getCurrentReadings = () => {
    return metrics.map(metric => {
      const data = generateTimeSeriesData(metric.id, 1);
      const currentValue = data.data[data.data.length - 1];
      
      let status = 'normal';
      if (metric.id === 'heart_rate') {
        status = currentValue < 60 || currentValue > 100 ? 'warning' : 'normal';
      } else if (metric.id === 'temperature') {
        status = currentValue < 36.1 || currentValue > 37.2 ? 'warning' : 'normal';
      } else if (metric.id === 'oxygen_saturation') {
        status = currentValue < 95 ? 'critical' : 'normal';
      }
      
      return {
        ...metric,
        value: currentValue,
        status,
        timestamp: new Date().toLocaleString(),
      };
    });
  };

  const getStatusColor = (status) => {
    switch (status) {
      case 'normal': return 'text-green-600 bg-green-50';
      case 'warning': return 'text-yellow-600 bg-yellow-50';
      case 'critical': return 'text-red-600 bg-red-50';
      default: return 'text-gray-600 bg-gray-50';
    }
  };

  return (
    <div className="p-6 max-w-7xl mx-auto">
      {/* Header */}
      <div className="mb-8">
        <h1 className="text-3xl font-bold text-gray-900 mb-2">Health Monitoring</h1>
        <p className="text-gray-600">Real-time vital signs monitoring and health trends analysis</p>
      </div>

      {/* Controls */}
      <div className="bg-white rounded-lg shadow-sm border border-gray-200 p-6 mb-6">
        <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
          {/* Patient Selection */}
          <div>
            <label htmlFor="patient-select" className="block text-sm font-medium text-gray-700 mb-2">
              Select Patient
            </label>
            <select
              id="patient-select"
              value={selectedPatient}
              onChange={(e) => setSelectedPatient(e.target.value)}
              className="w-full px-3 py-2 border border-gray-300 rounded-md focus:outline-none focus:ring-2 focus:ring-blue-500"
            >
              <option value="">All Patients</option>
              {patients.map(patient => (
                <option key={patient.id} value={patient.id}>
                  {patient.name} ({patient.nhsNumber})
                </option>
              ))}
            </select>
          </div>

          {/* Time Range */}
          <div>
            <label htmlFor="time-range" className="block text-sm font-medium text-gray-700 mb-2">
              Time Range
            </label>
            <select
              id="time-range"
              value={timeRange}
              onChange={(e) => setTimeRange(e.target.value)}
              className="w-full px-3 py-2 border border-gray-300 rounded-md focus:outline-none focus:ring-2 focus:ring-blue-500"
            >
              <option value="24h">Last 24 Hours</option>
              <option value="7d">Last 7 Days</option>
              <option value="30d">Last 30 Days</option>
            </select>
          </div>

          {/* Metrics Selection */}
          <div>
            <label className="block text-sm font-medium text-gray-700 mb-2">
              Metrics to Display
            </label>
            <div className="space-y-2 max-h-32 overflow-y-auto">
              {metrics.map(metric => (
                <label key={metric.id} className="flex items-center">
                  <input
                    type="checkbox"
                    checked={selectedMetrics.includes(metric.id)}
                    onChange={(e) => {
                      if (e.target.checked) {
                        setSelectedMetrics([...selectedMetrics, metric.id]);
                      } else {
                        setSelectedMetrics(selectedMetrics.filter(m => m !== metric.id));
                      }
                    }}
                    className="mr-2 h-4 w-4 text-blue-600 focus:ring-blue-500 border-gray-300 rounded"
                  />
                  <span className="text-sm text-gray-700">{metric.name}</span>
                </label>
              ))}
            </div>
          </div>
        </div>
      </div>

      {/* Current Readings */}
      <div className="mb-8">
        <h2 className="text-xl font-semibold text-gray-900 mb-4">Current Readings</h2>
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
          {getCurrentReadings().map(reading => (
            <div key={reading.id} className="bg-white rounded-lg shadow-sm border border-gray-200 p-4">
              <div className="flex items-center justify-between mb-2">
                <h3 className="text-sm font-medium text-gray-900">{reading.name}</h3>
                <span className={`px-2 py-1 rounded-full text-xs font-medium ${getStatusColor(reading.status)}`}>
                  {reading.status.toUpperCase()}
                </span>
              </div>
              <div className="text-2xl font-bold text-gray-900 mb-1">
                {reading.value} {reading.unit}
              </div>
              <div className="text-xs text-gray-500">
                Normal: {reading.normalRange}
              </div>
              <div className="text-xs text-gray-400 mt-2">
                Last updated: {reading.timestamp}
              </div>
            </div>
          ))}
        </div>
      </div>

      {/* Charts */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6 mb-8">
        {/* Trends Chart */}
        <div className="lg:col-span-2 bg-white rounded-lg shadow-sm border border-gray-200 p-6">
          <h2 className="text-xl font-semibold text-gray-900 mb-4">Vital Signs Trends</h2>
          <div className="h-80">
            <Line data={createLineChartData()} options={lineChartOptions} />
          </div>
        </div>

        {/* Alert Status */}
        <div className="bg-white rounded-lg shadow-sm border border-gray-200 p-6">
          <h2 className="text-xl font-semibold text-gray-900 mb-4">Alert Status</h2>
          <div className="h-64">
            <Pie 
              data={alertStatusData} 
              options={{
                responsive: true,
                maintainAspectRatio: false,
                plugins: {
                  legend: {
                    position: 'bottom',
                  },
                },
              }}
            />
          </div>
        </div>
      </div>

      {/* Recent Alerts */}
      <div className="bg-white rounded-lg shadow-sm border border-gray-200 p-6">
        <h2 className="text-xl font-semibold text-gray-900 mb-4">Recent Alerts</h2>
        <div className="space-y-3">
          {[
            { time: '10:45 AM', patient: 'John Smith', metric: 'Heart Rate', value: '105 bpm', status: 'warning' },
            { time: '09:30 AM', patient: 'Sarah Johnson', metric: 'Blood Pressure', value: '145/95 mmHg', status: 'warning' },
            { time: '08:15 AM', patient: 'Michael Brown', metric: 'Temperature', value: '38.2°C', status: 'critical' },
          ].map((alert, index) => (
            <div key={index} className="flex items-center justify-between p-3 rounded-lg border border-gray-200">
              <div className="flex items-center space-x-4">
                <div className={`w-3 h-3 rounded-full ${
                  alert.status === 'critical' ? 'bg-red-500' : 'bg-yellow-500'
                }`}></div>
                <div>
                  <div className="font-medium text-gray-900">{alert.patient}</div>
                  <div className="text-sm text-gray-600">
                    {alert.metric}: {alert.value}
                  </div>
                </div>
              </div>
              <div className="text-sm text-gray-500">{alert.time}</div>
            </div>
          ))}
        </div>
      </div>
    </div>
  );
};

export default HealthMonitoring;
