import { useAuthStore } from '../store/authStore';

export default function Dashboard() {
  const user = useAuthStore((s) => s.user)!;
  const rows = [
    ['Email', user.email],
    ['Role', user.role],
    ['Email verified', user.isEmailVerified ? 'Yes' : 'No'],
    ['Member since', new Date(user.createdAt).toLocaleDateString()],
  ];
  return (
    <div className="max-w-3xl">
      <h1 className="text-2xl font-semibold">Welcome, {user.name}</h1>
      <p className="mt-2 text-sm text-mute">Your identity layer is active. Upload files, share them under policy, and review who accessed what.</p>
      <dl className="mt-8 divide-y divide-line rounded-lg border border-line bg-panel">
        {rows.map(([k, v]) => (
          <div key={k} className="flex justify-between px-4 py-3 text-sm">
            <dt className="text-mute">{k}</dt>
            <dd className="font-medium">{v}</dd>
          </div>
        ))}
      </dl>
    </div>
  );
}
