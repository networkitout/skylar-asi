import React from 'react';
import { BrowserRouter, Routes, Route, Navigate } from 'react-router-dom';
import { AuthProvider, useAuth } from './context/AuthContext';
import Layout from './components/Layout';
import Login from './pages/Login';
import Dashboard from './pages/Dashboard';
import Zones from './pages/Zones';
import ZoneDetail from './pages/ZoneDetail';
import DNSRecords from './pages/DNSRecords';
import SecuritySettings from './pages/SecuritySettings';
import TrafficMetrics from './pages/TrafficMetrics';
import Reachability from './pages/Reachability';
import Exposure from './pages/Exposure';
import Reports from './pages/Reports';
import UserManagement from './pages/UserManagement';
import AuditLog from './pages/AuditLog';
import Settings from './pages/Settings';
import Wordmark from './components/Wordmark';
import './styles/skylar.css';

const ProtectedRoute = ({ children, adminOnly = false }) => {
  const { user, loading } = useAuth();

  if (loading) {
    return (
      <div className="loading-screen">
        <div className="loading-content">
          <Wordmark size={28} />
          <div className="spinner" />
        </div>
      </div>
    );
  }
  
  if (!user) {
    return <Navigate to="/login" />;
  }
  
  if (adminOnly && !user.is_admin) {
    return <Navigate to="/" />;
  }
  
  return children;
};

function App() {
  return (
    <AuthProvider>
      <BrowserRouter>
        <Routes>
          <Route path="/login" element={<Login />} />
          <Route path="/" element={
            <ProtectedRoute>
              <Layout />
            </ProtectedRoute>
          }>
            <Route index element={<Dashboard />} />
            <Route path="zones" element={<Zones />} />
            <Route path="zones/:zoneId" element={<ZoneDetail />} />
            <Route path="dns-records" element={<DNSRecords />} />
            <Route path="security" element={<SecuritySettings />} />
            <Route path="traffic" element={<TrafficMetrics />} />
            <Route path="reachability" element={<Reachability />} />
            <Route path="exposure" element={<Exposure />} />
            <Route path="reports" element={<Reports />} />
            <Route path="users" element={
              <ProtectedRoute adminOnly>
                <UserManagement />
              </ProtectedRoute>
            } />
            <Route path="audit-log" element={
              <ProtectedRoute adminOnly>
                <AuditLog />
              </ProtectedRoute>
            } />
            <Route path="settings" element={<Settings />} />
          </Route>
        </Routes>
      </BrowserRouter>
    </AuthProvider>
  );
}

export default App;
