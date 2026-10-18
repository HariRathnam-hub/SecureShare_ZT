import { useEffect, useRef, useState } from 'react';
import { Link, useSearchParams } from 'react-router-dom';
import { Alert } from '../components/ui';
import AuthLayout from '../layouts/AuthLayout';
import { getErrorMessage } from '../lib/api';
import { authApi } from '../services/authApi';

export default function VerifyEmail() {
  const token = useSearchParams()[0].get('token');
  const [state, setState] = useState<{ kind: 'loading' | 'ok' | 'error'; msg?: string }>({ kind: 'loading' });
  const ran = useRef(false); // token is single-use: guard against StrictMode double-invoke

  useEffect(() => {
    if (ran.current) return;
    ran.current = true;
    if (!token) return setState({ kind: 'error', msg: 'This verification link is missing its token.' });
    authApi
      .verifyEmail(token)
      .then(() => setState({ kind: 'ok' }))
      .catch((e) => setState({ kind: 'error', msg: getErrorMessage(e) }));
  }, [token]);

  return (
    <AuthLayout title="Email verification">
      {state.kind === 'loading' && <p className="text-sm text-mute">Verifying your email…</p>}
      {state.kind === 'ok' && <Alert kind="success">Email verified. You can now sign in.</Alert>}
      {state.kind === 'error' && <Alert kind="error">{state.msg}</Alert>}
      <Link to="/login" className="mt-6 inline-block text-sm text-mute hover:text-fog">Go to sign in</Link>
    </AuthLayout>
  );
}
