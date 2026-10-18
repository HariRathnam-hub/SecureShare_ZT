import { useCallback, useEffect, useState } from 'react';
import { Alert } from '../components/ui';
import { getErrorMessage } from '../lib/api';
import { userApi } from '../services/authApi';
import { useAuthStore, User } from '../store/authStore';

export default function AdminUsers() {
  const me = useAuthStore((s) => s.user)!;
  const [users, setUsers] = useState<User[]>([]);
  const [error, setError] = useState('');

  const load = useCallback(() => {
    userApi.list().then((d) => setUsers(d.users)).catch((e) => setError(getErrorMessage(e)));
  }, []);
  useEffect(load, [load]);

  const toggle = async (u: User) => {
    try {
      await userApi.setRole(u.id, u.role === 'admin' ? 'user' : 'admin');
      load();
    } catch (e) {
      setError(getErrorMessage(e));
    }
  };

  return (
    <div className="max-w-4xl">
      <h1 className="text-2xl font-semibold">Users</h1>
      {error && <div className="mt-4"><Alert kind="error">{error}</Alert></div>}
      <div className="mt-6 overflow-x-auto rounded-lg border border-line">
        <table className="w-full text-left text-sm">
          <thead className="bg-panel text-mute">
            <tr><th className="px-4 py-3 font-medium">Name</th><th className="px-4 py-3 font-medium">Email</th><th className="px-4 py-3 font-medium">Role</th><th className="px-4 py-3" /></tr>
          </thead>
          <tbody className="divide-y divide-line">
            {users.map((u) => (
              <tr key={u.id}>
                <td className="px-4 py-3">{u.name}</td>
                <td className="px-4 py-3 text-mute">{u.email}</td>
                <td className="px-4 py-3">{u.role}</td>
                <td className="px-4 py-3 text-right">
                  {u.id !== me.id && (
                    <button onClick={() => toggle(u)} className="text-signal hover:underline">
                      Make {u.role === 'admin' ? 'user' : 'admin'}
                    </button>
                  )}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}
