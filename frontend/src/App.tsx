import { useEffect } from 'react';
import { Navigate, Route, Routes } from 'react-router-dom';
import ProtectedRoute from './components/ProtectedRoute';
import DashboardLayout from './layouts/DashboardLayout';
import { refreshSession } from './lib/api';
import AdminUsers from './pages/AdminUsers';
import Dashboard from './pages/Dashboard';
import ForgotPassword from './pages/ForgotPassword';
import Login from './pages/Login';
import SecurityDashboard from './pages/SecurityDashboard';
import Register from './pages/Register';
import ResetPassword from './pages/ResetPassword';
import VerifyEmail from './pages/VerifyEmail';
import AccessRequests from './pages/AccessRequests';
import DataRoomDetail from './pages/DataRoomDetail';
import DataRooms from './pages/DataRooms';
import FileDetails from './pages/FileDetails';
import Files from './pages/Files';
import SharedLinkOpen from './pages/SharedLinkOpen';
import SharedLinks from './pages/SharedLinks';
import UploadFile from './pages/UploadFile';
import { useAuthStore } from './store/authStore';

export default function App() {
  // Restore the session from the httpOnly refresh cookie on every page load.
  useEffect(() => {
    refreshSession()
      .catch(() => useAuthStore.getState().clearSession())
      .finally(() => useAuthStore.getState().finishInit());
  }, []);

  return (
    <Routes>
      <Route path="/login" element={<Login />} />
      <Route path="/register" element={<Register />} />
      <Route path="/forgot-password" element={<ForgotPassword />} />
      <Route path="/reset-password" element={<ResetPassword />} />
      <Route path="/verify-email" element={<VerifyEmail />} />

      <Route element={<ProtectedRoute />}>
        <Route element={<DashboardLayout />}>
          <Route path="/dashboard" element={<Dashboard />} />
          <Route path="/files" element={<Files />} />
          <Route path="/files/upload" element={<UploadFile />} />
          <Route path="/files/:id" element={<FileDetails />} />
          <Route path="/links" element={<SharedLinks />} />
          <Route path="/s/:token" element={<SharedLinkOpen />} />
          <Route path="/rooms" element={<DataRooms />} />
          <Route path="/rooms/:id" element={<DataRoomDetail />} />
          <Route path="/access-requests" element={<AccessRequests />} />
          <Route element={<ProtectedRoute roles={['admin']} />}>
            <Route path="/admin/users" element={<AdminUsers />} />
            <Route path="/admin/security" element={<SecurityDashboard />} />
          </Route>
        </Route>
      </Route>

      <Route path="*" element={<Navigate to="/dashboard" replace />} />
    </Routes>
  );
}
