import { Navigate, Outlet, useLocation } from 'react-router-dom';
import { Role, useAuthStore } from '../store/authStore';

export default function ProtectedRoute({ roles }: { roles?: Role[] }) {
  const { user, isInitializing } = useAuthStore();
  const location = useLocation();

  if (isInitializing) {
    return <div className="grid min-h-screen place-items-center text-sm text-mute">Verifying your session…</div>;
  }
  if (!user) return <Navigate to="/login" replace state={{ from: location }} />;
  // UI guard only. The API enforces RBAC independently.
  if (roles && !roles.includes(user.role)) return <Navigate to="/dashboard" replace />;
  return <Outlet />;
}
