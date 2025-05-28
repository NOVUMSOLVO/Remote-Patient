import React, { useState, useEffect } from 'react';
import { BarChart3, Download, Filter, Calendar, FileText, TrendingUp, Users, Activity, AlertTriangle, Clock } from 'lucide-react';
import { Line, Bar, Pie, Doughnut } from 'react-chartjs-2';
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
import './Reports.css';

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

const Reports = () => {
  const [activeTab, setActiveTab] = useState('analytics');
  const [dateRange, setDateRange] = useState('last30days');
  const [selectedMetrics, setSelectedMetrics] = useState(['patients', 'vitals', 'alerts']);
  const [reportData, setReportData] = useState({});
  const [loading, setLoading] = useState(true);
  const [customReports, setCustomReports] = useState([]);

  useEffect(() => {
    fetchReportData();
    fetchCustomReports();
  }, [dateRange, selectedMetrics]);

  const fetchReportData = async () => {
    try {
      setLoading(true);
      // API call would go here
      const mockData = {
        overview: {
          totalPatients: 1247,
          activePatients: 892,
          newPatientsThisMonth: 45,
          averageReadingsPerPatient: 28,
          criticalAlerts: 12,
          resolvedAlerts: 156,
          deviceUptime: 98.5,
          complianceRate: 94.2
        },
        patientTrends: {
          labels: ['Jan', 'Feb', 'Mar', 'Apr', 'May', 'Jun'],
          datasets: [
            {
              label: 'Active Patients',
              data: [820, 845, 867, 888, 876, 892],
              borderColor: 'rgb(59, 130, 246)',
              backgroundColor: 'rgba(59, 130, 246, 0.1)',
              tension: 0.4
            },
            {
              label: 'New Enrollments',
              data: [35, 42, 38, 51, 44, 45],
              borderColor: 'rgb(16, 185, 129)',
              backgroundColor: 'rgba(16, 185, 129, 0.1)',
              tension: 0.4
            }
          ]
        },
        vitalsTrends: {
          labels: ['Week 1', 'Week 2', 'Week 3', 'Week 4'],
          datasets: [
            {
              label: 'Blood Pressure Readings',
              data: [2340, 2567, 2445, 2678],
              backgroundColor: 'rgba(99, 102, 241, 0.8)'
            },
            {
              label: 'Heart Rate Readings',
              data: [1890, 2123, 2034, 2156],
              backgroundColor: 'rgba(236, 72, 153, 0.8)'
            },
            {
              label: 'Weight Readings',
              data: [1456, 1523, 1489, 1567],
              backgroundColor: 'rgba(34, 197, 94, 0.8)'
            }
          ]
        },
        alertsDistribution: {
          labels: ['Critical', 'High', 'Medium', 'Low'],
          datasets: [
            {
              data: [12, 34, 78, 156],
              backgroundColor: [
                'rgba(239, 68, 68, 0.8)',
                'rgba(245, 158, 11, 0.8)',
                'rgba(59, 130, 246, 0.8)',
                'rgba(16, 185, 129, 0.8)'
              ]
            }
          ]
        },
        complianceByCondition: {
          labels: ['Hypertension', 'Diabetes', 'Heart Disease', 'COPD', 'Other'],
          datasets: [
            {
              data: [95.2, 91.8, 93.4, 89.7, 92.1],
              backgroundColor: [
                'rgba(59, 130, 246, 0.8)',
                'rgba(16, 185, 129, 0.8)',
                'rgba(245, 158, 11, 0.8)',
                'rgba(239, 68, 68, 0.8)',
                'rgba(156, 163, 175, 0.8)'
              ]
            }
          ]
        }
      };
      setReportData(mockData);
    } catch (error) {
      console.error('Error fetching report data:', error);
    } finally {
      setLoading(false);
    }
  };

  const fetchCustomReports = async () => {
    try {
      // API call would go here
      const mockReports = [
        {
          id: 1,
          name: 'Monthly Patient Summary',
          description: 'Comprehensive monthly overview of patient metrics',
          lastGenerated: new Date(Date.now() - 1000 * 60 * 60 * 24),
          type: 'scheduled',
          frequency: 'monthly'
        },
        {
          id: 2,
          name: 'Critical Alerts Report',
          description: 'Weekly summary of critical patient alerts',
          lastGenerated: new Date(Date.now() - 1000 * 60 * 60 * 24 * 7),
          type: 'scheduled',
          frequency: 'weekly'
        },
        {
          id: 3,
          name: 'Device Performance Analysis',
          description: 'Quarterly analysis of device performance and reliability',
          lastGenerated: new Date(Date.now() - 1000 * 60 * 60 * 24 * 30),
          type: 'adhoc',
          frequency: 'quarterly'
        }
      ];
      setCustomReports(mockReports);
    } catch (error) {
      console.error('Error fetching custom reports:', error);
    }
  };

  const generateReport = async (reportType, format = 'pdf') => {
    try {
      // API call would go here
      console.log(`Generating ${reportType} report in ${format} format`);
      // This would typically trigger a download
    } catch (error) {
      console.error('Error generating report:', error);
    }
  };

  const chartOptions = {
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
        beginAtZero: true,
      },
    },
  };

  const pieChartOptions = {
    responsive: true,
    maintainAspectRatio: false,
    plugins: {
      legend: {
        position: 'right',
      },
    },
  };

  if (loading) {
    return (
      <div className="flex justify-center items-center h-64">
        <div className="animate-spin rounded-full h-32 w-32 border-b-2 border-blue-500"></div>
      </div>
    );
  }

  return (
    <div className="reports-container">
      {/* Header */}
      <div className="reports-header">
        <h1 className="text-2xl font-bold text-gray-900 mb-6">Reports & Analytics</h1>
        
        {/* Controls */}
        <div className="controls-section bg-white p-4 rounded-lg shadow-sm mb-6">
          <div className="flex flex-wrap items-center justify-between gap-4">
            <div className="flex items-center space-x-4">
              <select
                value={dateRange}
                onChange={(e) => setDateRange(e.target.value)}
                className="px-3 py-2 border border-gray-300 rounded-md focus:ring-2 focus:ring-blue-500 focus:border-transparent"
              >
                <option value="last7days">Last 7 Days</option>
                <option value="last30days">Last 30 Days</option>
                <option value="last3months">Last 3 Months</option>
                <option value="last6months">Last 6 Months</option>
                <option value="lastyear">Last Year</option>
                <option value="custom">Custom Range</option>
              </select>
              
              <div className="flex items-center space-x-2">
                <Filter className="h-5 w-5 text-gray-400" />
                <span className="text-sm text-gray-600">Metrics:</span>
                <div className="flex space-x-2">
                  {['patients', 'vitals', 'alerts', 'devices'].map((metric) => (
                    <label key={metric} className="flex items-center">
                      <input
                        type="checkbox"
                        checked={selectedMetrics.includes(metric)}
                        onChange={(e) => {
                          if (e.target.checked) {
                            setSelectedMetrics([...selectedMetrics, metric]);
                          } else {
                            setSelectedMetrics(selectedMetrics.filter(m => m !== metric));
                          }
                        }}
                        className="mr-2"
                      />
                      <span className="text-sm capitalize">{metric}</span>
                    </label>
                  ))}
                </div>
              </div>
            </div>
            
            <div className="flex items-center space-x-2">
              <button
                onClick={() => generateReport('comprehensive', 'pdf')}
                className="flex items-center px-4 py-2 bg-blue-600 text-white rounded-md hover:bg-blue-700 transition-colors"
              >
                <Download className="h-4 w-4 mr-2" />
                Export PDF
              </button>
              <button
                onClick={() => generateReport('comprehensive', 'excel')}
                className="flex items-center px-4 py-2 bg-green-600 text-white rounded-md hover:bg-green-700 transition-colors"
              >
                <Download className="h-4 w-4 mr-2" />
                Export Excel
              </button>
            </div>
          </div>
        </div>

        {/* Tabs */}
        <div className="tabs-container">
          <button
            onClick={() => setActiveTab('analytics')}
            className={`tab-button ${activeTab === 'analytics' ? 'active' : ''}`}
          >
            <BarChart3 className="h-5 w-5 mr-2" />
            Analytics Dashboard
          </button>
          <button
            onClick={() => setActiveTab('custom')}
            className={`tab-button ${activeTab === 'custom' ? 'active' : ''}`}
          >
            <FileText className="h-5 w-5 mr-2" />
            Custom Reports
          </button>
        </div>
      </div>

      {activeTab === 'analytics' ? (
        <div className="analytics-dashboard">
          {/* Key Metrics */}
          <div className="metrics-grid mb-8">
            <div className="metric-card">
              <div className="flex items-center justify-between">
                <div>
                  <p className="text-sm font-medium text-gray-600">Total Patients</p>
                  <p className="text-2xl font-bold text-gray-900">{reportData.overview?.totalPatients?.toLocaleString()}</p>
                </div>
                <Users className="h-8 w-8 text-blue-500" />
              </div>
              <div className="mt-2 flex items-center text-sm">
                <TrendingUp className="h-4 w-4 text-green-500 mr-1" />
                <span className="text-green-600">+5.2% from last month</span>
              </div>
            </div>

            <div className="metric-card">
              <div className="flex items-center justify-between">
                <div>
                  <p className="text-sm font-medium text-gray-600">Active Patients</p>
                  <p className="text-2xl font-bold text-gray-900">{reportData.overview?.activePatients?.toLocaleString()}</p>
                </div>
                <Activity className="h-8 w-8 text-green-500" />
              </div>
              <div className="mt-2 flex items-center text-sm">
                <TrendingUp className="h-4 w-4 text-green-500 mr-1" />
                <span className="text-green-600">+2.1% from last month</span>
              </div>
            </div>

            <div className="metric-card">
              <div className="flex items-center justify-between">
                <div>
                  <p className="text-sm font-medium text-gray-600">Critical Alerts</p>
                  <p className="text-2xl font-bold text-gray-900">{reportData.overview?.criticalAlerts}</p>
                </div>
                <AlertTriangle className="h-8 w-8 text-red-500" />
              </div>
              <div className="mt-2 flex items-center text-sm">
                <span className="text-red-600">-15.3% from last month</span>
              </div>
            </div>

            <div className="metric-card">
              <div className="flex items-center justify-between">
                <div>
                  <p className="text-sm font-medium text-gray-600">Compliance Rate</p>
                  <p className="text-2xl font-bold text-gray-900">{reportData.overview?.complianceRate}%</p>
                </div>
                <Clock className="h-8 w-8 text-purple-500" />
              </div>
              <div className="mt-2 flex items-center text-sm">
                <TrendingUp className="h-4 w-4 text-green-500 mr-1" />
                <span className="text-green-600">+1.8% from last month</span>
              </div>
            </div>
          </div>

          {/* Charts Grid */}
          <div className="charts-grid">
            {/* Patient Trends */}
            <div className="chart-card">
              <h3 className="chart-title">Patient Trends</h3>
              <div className="chart-container">
                <Line data={reportData.patientTrends} options={chartOptions} />
              </div>
            </div>

            {/* Vitals Overview */}
            <div className="chart-card">
              <h3 className="chart-title">Vital Signs Readings</h3>
              <div className="chart-container">
                <Bar data={reportData.vitalsTrends} options={chartOptions} />
              </div>
            </div>

            {/* Alerts Distribution */}
            <div className="chart-card">
              <h3 className="chart-title">Alerts Distribution</h3>
              <div className="chart-container">
                <Doughnut data={reportData.alertsDistribution} options={pieChartOptions} />
              </div>
            </div>

            {/* Compliance by Condition */}
            <div className="chart-card">
              <h3 className="chart-title">Compliance by Condition</h3>
              <div className="chart-container">
                <Bar 
                  data={reportData.complianceByCondition} 
                  options={{
                    ...chartOptions,
                    scales: {
                      y: {
                        beginAtZero: true,
                        max: 100,
                        ticks: {
                          callback: function(value) {
                            return value + '%';
                          }
                        }
                      }
                    }
                  }} 
                />
              </div>
            </div>
          </div>
        </div>
      ) : (
        /* Custom Reports */
        <div className="custom-reports">
          <div className="reports-section">
            <div className="flex items-center justify-between mb-6">
              <h2 className="text-lg font-semibold text-gray-900">Custom Reports</h2>
              <button className="px-4 py-2 bg-blue-600 text-white rounded-md hover:bg-blue-700 transition-colors">
                Create New Report
              </button>
            </div>

            <div className="reports-list space-y-4">
              {customReports.map((report) => (
                <div key={report.id} className="report-item">
                  <div className="flex items-center justify-between">
                    <div className="flex-1">
                      <h3 className="text-lg font-semibold text-gray-900">{report.name}</h3>
                      <p className="text-gray-600 mb-2">{report.description}</p>
                      <div className="flex items-center space-x-4 text-sm text-gray-500">
                        <span>Type: {report.type}</span>
                        <span>Frequency: {report.frequency}</span>
                        <span>Last generated: {report.lastGenerated.toLocaleDateString()}</span>
                      </div>
                    </div>
                    
                    <div className="flex items-center space-x-2">
                      <button
                        onClick={() => generateReport(report.id, 'pdf')}
                        className="px-3 py-2 bg-gray-100 text-gray-700 rounded-md hover:bg-gray-200 transition-colors"
                      >
                        Generate PDF
                      </button>
                      <button
                        onClick={() => generateReport(report.id, 'excel')}
                        className="px-3 py-2 bg-gray-100 text-gray-700 rounded-md hover:bg-gray-200 transition-colors"
                      >
                        Generate Excel
                      </button>
                      <button className="px-3 py-2 text-blue-600 hover:text-blue-800 transition-colors">
                        Edit
                      </button>
                    </div>
                  </div>
                </div>
              ))}
            </div>
          </div>

          {/* Report Templates */}
          <div className="templates-section mt-8">
            <h2 className="text-lg font-semibold text-gray-900 mb-6">Report Templates</h2>
            
            <div className="templates-grid">
              <div className="template-card">
                <FileText className="h-8 w-8 text-blue-500 mb-3" />
                <h3 className="text-lg font-semibold text-gray-900 mb-2">Patient Summary</h3>
                <p className="text-gray-600 mb-4">Comprehensive overview of patient health metrics and trends</p>
                <button className="w-full px-4 py-2 bg-blue-600 text-white rounded-md hover:bg-blue-700 transition-colors">
                  Use Template
                </button>
              </div>

              <div className="template-card">
                <BarChart3 className="h-8 w-8 text-green-500 mb-3" />
                <h3 className="text-lg font-semibold text-gray-900 mb-2">Performance Analytics</h3>
                <p className="text-gray-600 mb-4">Detailed analysis of system performance and device metrics</p>
                <button className="w-full px-4 py-2 bg-green-600 text-white rounded-md hover:bg-green-700 transition-colors">
                  Use Template
                </button>
              </div>

              <div className="template-card">
                <AlertTriangle className="h-8 w-8 text-red-500 mb-3" />
                <h3 className="text-lg font-semibold text-gray-900 mb-2">Alerts Analysis</h3>
                <p className="text-gray-600 mb-4">Summary of alerts, incidents, and response times</p>
                <button className="w-full px-4 py-2 bg-red-600 text-white rounded-md hover:bg-red-700 transition-colors">
                  Use Template
                </button>
              </div>

              <div className="template-card">
                <Users className="h-8 w-8 text-purple-500 mb-3" />
                <h3 className="text-lg font-semibold text-gray-900 mb-2">Compliance Report</h3>
                <p className="text-gray-600 mb-4">Patient compliance metrics and improvement recommendations</p>
                <button className="w-full px-4 py-2 bg-purple-600 text-white rounded-md hover:bg-purple-700 transition-colors">
                  Use Template
                </button>
              </div>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};

export default Reports;
