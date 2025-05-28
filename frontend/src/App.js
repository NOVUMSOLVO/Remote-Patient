import React from 'react';
import { BrowserRouter as Router, Routes, Route, Navigate } from 'react-router-dom';
import { QueryClient, QueryClientProvider } from 'react-query';
import { ToastContainer } from 'react-toastify';
import 'react-toastify/dist/ReactToastify.css';

// Layout Components
import Layout from './components/shared/Layout';
import ProtectedRoute from './components/shared/ProtectedRoute';

// Pages
import Login from './pages/Login';
import Dashboard from './pages/Dashboard';
import PatientManagement from './pages/PatientManagement';
import DeviceManagement from './pages/DeviceManagement';
import HealthMonitoring from './pages/HealthMonitoring';
import AlertsCenter from './pages/AlertsCenter';
import Communication from './pages/Communication';
import Reports from './pages/Reports';
import AdminPanel from './pages/AdminPanel';
import PatientProfile from './pages/PatientProfile';
import Settings from './pages/Settings';

// Contexts
import { AuthProvider } from './contexts/AuthContext';
import { ThemeProvider } from './contexts/ThemeContext';

// Styles
import './styles/index.css';

// Create Query Client
const queryClient = new QueryClient({
  defaultOptions: {
    queries: {
      refetchOnWindowFocus: false,
      retry: 1,
      staleTime: 5 * 60 * 1000, // 5 minutes
    },
  },
});

function App() {
  return (
    <QueryClientProvider client={queryClient}>
      <ThemeProvider>
        <AuthProvider>
          <Router>
            <div className="App min-h-screen bg-gray-50">
              <Routes>
                {/* Public Routes */}
                <Route path="/login" element={<Login />} />
                
                {/* Protected Routes */}
                <Route path="/" element={<ProtectedRoute><Layout /></ProtectedRoute>}>
                  <Route index element={<Navigate to="/dashboard" replace />} />
                  <Route path="dashboard" element={<Dashboard />} />
                  
                  {/* Patient Management */}
                  <Route path="patients" element={<PatientManagement />} />
                  <Route path="patients/:id" element={<PatientProfile />} />
                  
                  {/* Device Management */}
                  <Route path="devices" element={<DeviceManagement />} />
                  
                  {/* Health Monitoring */}
                  <Route path="monitoring" element={<HealthMonitoring />} />
                  
                  {/* Alerts & Notifications */}
                  <Route path="alerts" element={<AlertsCenter />} />
                  
                  {/* Communication */}
                  <Route path="communication" element={<Communication />} />
                  
                  {/* Reports & Analytics */}
                  <Route path="reports" element={<Reports />} />
                  
                  {/* Admin Panel */}
                  <Route path="admin" element={<AdminPanel />} />
                  
                  {/* Settings */}
                  <Route path="settings" element={<Settings />} />
                </Route>
                
                {/* 404 Route */}
                <Route path="*" element={<Navigate to="/dashboard" replace />} />
              </Routes>
              
              {/* Toast Notifications */}
              <ToastContainer
                position="top-right"
                autoClose={5000}
                hideProgressBar={false}
                newestOnTop={false}
                closeOnClick
                rtl={false}
                pauseOnFocusLoss
                draggable
                pauseOnHover
                theme="light"
              />
            </div>
          </Router>
        </AuthProvider>
      </ThemeProvider>
    </QueryClientProvider>
  );
}

export default App;
