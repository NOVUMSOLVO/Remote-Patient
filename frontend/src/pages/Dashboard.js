import React, { useState, useEffect } from 'react';
import { 
  UserGroupIcon,
  DevicePhoneMobileIcon,
  HeartIcon,
  BellIcon,
  ArrowUpIcon,
  ArrowDownIcon,
  ExclamationTriangleIcon
} from '@heroicons/react/24/outline';
import { Line, Doughnut, Bar } from 'react-chartjs-2';
import {
  Chart as ChartJS,
  CategoryScale,
  LinearScale,
  PointElement,
  LineElement,
  Title,
  Tooltip,
  Legend,
  ArcElement,
  BarElement,
} from 'chart.js';
import { useAuth } from '../contexts/AuthContext';
import LoadingSpinner from '../components/shared/LoadingSpinner';

// Register ChartJS components
ChartJS.register(
  CategoryScale,
  LinearScale,
  PointElement,
  LineElement,
  Title,
  Tooltip,
  Legend,
  ArcElement,
  BarElement
);

const Dashboard = () => {
  const { user } = useAuth();
  const [loading, setLoading] = useState(true);
  const [dashboardData, setDashboardData] = useState(null);

  // Mock data - would come from API
  useEffect(() => {
    const fetchDashboardData = async () => {
      // Simulate API call
      setTimeout(() => {
        setDashboardData({
          stats: {
            totalPatients: 1247,
            activeDevices: 892,
            criticalAlerts: 23,
            healthReadings: 15673,
            patientsChange: 12,
            devicesChange: -3,
            alertsChange: 8,
            readingsChange: 156
          },
          recentAlerts: [
            {
              id: 1,
              patient: 'John Smith',
              type: 'Heart Rate',
              severity: 'critical',
              value: '120 BPM',
              time: '5 min ago'
            },
            {
              id: 2,
              patient: 'Mary Johnson',
              type: 'Blood Pressure',
              severity: 'warning',
              value: '160/95 mmHg',
              time: '12 min ago'
            },
            {
              id: 3,
              patient: 'Robert Davis',
              type: 'Temperature',
              severity: 'normal',
              value: '99.1°F',
              time: '25 min ago'
            }
          ],
          vitalsData: {
            labels: ['Mon', 'Tue', 'Wed', 'Thu', 'Fri', 'Sat', 'Sun'],
            datasets: [
              {
                label: 'Heart Rate (avg)',
                data: [72, 75, 78, 74, 76, 73, 75],
                borderColor: 'rgb(0, 94, 184)',
                backgroundColor: 'rgba(0, 94, 184, 0.1)',
                tension: 0.4,
              },
              {
                label: 'Blood Pressure (systolic)',
                data: [120, 125, 122, 128, 124, 126, 123],
                borderColor: 'rgb(218, 41, 28)',
                backgroundColor: 'rgba(218, 41, 28, 0.1)',
                tension: 0.4,
              }
            ]
          },
          deviceStatus: {
            labels: ['Connected', 'Disconnected', 'Low Battery'],
            datasets: [{
              data: [785, 67, 40],
              backgroundColor: [
                'rgb(0, 150, 57)',
                'rgb(218, 41, 28)',
                'rgb(250, 146, 0)'
              ]
            }]
          }
        });
        setLoading(false);
      }, 1000);
    };

    fetchDashboardData();
  }, []);

  if (loading) {
    return (
      <div className="flex justify-center items-center h-64">
        <LoadingSpinner size="large" text="Loading dashboard..." />
      </div>
    );
  }

  const StatCard = ({ title, value, change, icon: Icon, color = 'blue' }) => {
    const isPositive = change > 0;
    const colorClasses = {
      blue: 'bg-blue-500',
      green: 'bg-green-500',
      red: 'bg-red-500',
      orange: 'bg-orange-500'
    };

    return (
      <div className="card-nhs">
        <div className="card-nhs-body">
          <div className="flex items-center">
            <div className={`p-3 rounded-lg ${colorClasses[color]} mr-4`}>
              <Icon className="h-6 w-6 text-white" />
            </div>
            <div className="flex-1">
              <p className="text-sm font-medium text-gray-600">{title}</p>
              <p className="text-2xl font-bold text-gray-900">{value.toLocaleString()}</p>
            </div>
            <div className="flex items-center ml-4">
              {isPositive ? (
                <ArrowUpIcon className="h-4 w-4 text-green-500 mr-1" />
              ) : (
                <ArrowDownIcon className="h-4 w-4 text-red-500 mr-1" />
              )}
              <span className={`text-sm font-medium ${
                isPositive ? 'text-green-600' : 'text-red-600'
              }`}>
                {Math.abs(change)}
              </span>
            </div>
          </div>
        </div>
      </div>
    );
  };

  const AlertItem = ({ alert }) => {
    const severityColors = {
      critical: 'bg-red-100 text-red-800 border-red-200',
      warning: 'bg-yellow-100 text-yellow-800 border-yellow-200',
      normal: 'bg-green-100 text-green-800 border-green-200'
    };

    return (
      <div className="flex items-center justify-between py-3 border-b border-gray-200 last:border-b-0">
        <div className="flex items-center space-x-3">
          <div className={`p-2 rounded-full ${severityColors[alert.severity]}`}>
            <ExclamationTriangleIcon className="h-4 w-4" />
          </div>
          <div>
            <p className="text-sm font-medium text-gray-900">{alert.patient}</p>
            <p className="text-xs text-gray-500">{alert.type}: {alert.value}</p>
          </div>
        </div>
        <div className="text-right">
          <p className="text-xs text-gray-500">{alert.time}</p>
          <span className={`inline-flex px-2 py-1 text-xs font-medium rounded-full ${severityColors[alert.severity]}`}>
            {alert.severity}
          </span>
        </div>
      </div>
    );
  };

  return (
    <div className="space-y-6">
      {/* Welcome Header */}
      <div className="bg-gradient-to-r from-nhs-blue to-nhs-bright-blue rounded-lg p-6 text-white">
        <h1 className="text-2xl font-bold mb-2">
          Welcome back, {user?.first_name}!
        </h1>
        <p className="text-blue-100">
          Here's what's happening with your patients today
        </p>
      </div>

      {/* Stats Grid */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6">
        <StatCard
          title="Total Patients"
          value={dashboardData.stats.totalPatients}
          change={dashboardData.stats.patientsChange}
          icon={UserGroupIcon}
          color="blue"
        />
        <StatCard
          title="Active Devices"
          value={dashboardData.stats.activeDevices}
          change={dashboardData.stats.devicesChange}
          icon={DevicePhoneMobileIcon}
          color="green"
        />
        <StatCard
          title="Critical Alerts"
          value={dashboardData.stats.criticalAlerts}
          change={dashboardData.stats.alertsChange}
          icon={BellIcon}
          color="red"
        />
        <StatCard
          title="Health Readings"
          value={dashboardData.stats.healthReadings}
          change={dashboardData.stats.readingsChange}
          icon={HeartIcon}
          color="orange"
        />
      </div>

      {/* Charts and Alerts Row */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Vitals Trends Chart */}
        <div className="lg:col-span-2">
          <div className="card-nhs">
            <div className="card-nhs-header">
              <h3 className="text-lg font-medium text-gray-900">Weekly Vitals Trends</h3>
            </div>
            <div className="card-nhs-body">
              <div className="h-64">
                <Line
                  data={dashboardData.vitalsData}
                  options={{
                    responsive: true,
                    maintainAspectRatio: false,
                    plugins: {
                      legend: {
                        position: 'top',
                      },
                      title: {
                        display: false,
                      },
                    },
                    scales: {
                      y: {
                        beginAtZero: false,
                      },
                    },
                  }}
                />
              </div>
            </div>
          </div>
        </div>

        {/* Recent Alerts */}
        <div className="card-nhs">
          <div className="card-nhs-header">
            <h3 className="text-lg font-medium text-gray-900">Recent Alerts</h3>
          </div>
          <div className="card-nhs-body p-0">
            <div className="divide-y divide-gray-200">
              {dashboardData.recentAlerts.map((alert) => (
                <div key={alert.id} className="px-6 py-4">
                  <AlertItem alert={alert} />
                </div>
              ))}
            </div>
            <div className="px-6 py-4 bg-gray-50">
              <button className="text-sm text-nhs-blue hover:text-nhs-dark-blue font-medium">
                View all alerts →
              </button>
            </div>
          </div>
        </div>
      </div>

      {/* Device Status and Quick Actions */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* Device Status Chart */}
        <div className="card-nhs">
          <div className="card-nhs-header">
            <h3 className="text-lg font-medium text-gray-900">Device Status</h3>
          </div>
          <div className="card-nhs-body">
            <div className="h-64 flex justify-center">
              <Doughnut
                data={dashboardData.deviceStatus}
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

        {/* Quick Actions */}
        <div className="card-nhs">
          <div className="card-nhs-header">
            <h3 className="text-lg font-medium text-gray-900">Quick Actions</h3>
          </div>
          <div className="card-nhs-body">
            <div className="space-y-3">
              <button className="w-full btn-nhs-primary justify-start">
                Add New Patient
              </button>
              <button className="w-full btn-nhs-secondary justify-start">
                Register Device
              </button>
              <button className="w-full btn-nhs-secondary justify-start">
                Schedule Appointment
              </button>
              <button className="w-full btn-nhs-secondary justify-start">
                Generate Report
              </button>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
};

export default Dashboard;
