import { NavLink, Outlet, useNavigate } from 'react-router-dom';
import { Button } from '../components/ui';
import { authApi } from '../services/authApi';
import { useAuthStore } from '../store/authStore';

const link = ({ isActive }: { isActive: boolean }) =>
  `block rounded-md px-3 py-2 text-sm ${isActive ? 'bg-ink text-signal' : 'text-mute hover:text-fog'}`;

export default function DashboardLayout() {
  const user = useAuthStore((s) => s.user)!;
  const navigate = useNavigate();
  const signOut = async () => {
    await authApi.logout();
    navigate('/login', { replace: true });
  };

  return (
    <div className="min-h-screen lg:grid lg:grid-cols-[240px_1fr]">
      <aside className="flex flex-col gap-6 border-b border-line bg-panel p-4 lg:border-b-0 lg:border-r">
        <p className="px-3 text-base font-semibold tracking-tight">SecureShare ZT</p>
        <nav className="flex flex-wrap gap-1 lg:flex-col" aria-label="Main">
          <NavLink to="/dashboard" className={link}>Overview</NavLink>
          <NavLink to="/files" className={link}>Files</NavLink>
          <NavLink to="/links" className={link}>Shared links</NavLink>
          <NavLink to="/rooms" className={link}>Data rooms</NavLink>
          <NavLink to="/access-requests" className={link}>Access requests</NavLink>
          {user.role === 'admin' && <NavLink to="/admin/users" className={link}>Users</NavLink>}
          {user.role === 'admin' && <NavLink to="/admin/security" className={link}>Security</NavLink>}
        </nav>
        <div className="mt-auto hidden px-3 text-sm lg:block">
          <p className="truncate font-medium">{user.name}</p>
          <p className="truncate text-mute">{user.email}</p>
        </div>
      </aside>
      <div>
        <header className="flex items-center justify-between border-b border-line px-6 py-3">
          <p className="text-sm text-mute">Signed in as {user.role}</p>
          <Button variant="ghost" onClick={signOut}>Sign out</Button>
        </header>
        <main className="p-6"><Outlet /></main>
      </div>
    </div>
  );
}
