import { zodResolver } from '@hookform/resolvers/zod';
import { useState } from 'react';
import { useForm } from 'react-hook-form';
import { Link, Navigate, useLocation, useNavigate } from 'react-router-dom';
import { Alert, Button, Field } from '../components/ui';
import AuthLayout from '../layouts/AuthLayout';
import { getErrorMessage } from '../lib/api';
import { useTurnstile } from '../components/Turnstile';
import { LoginForm, loginSchema } from '../lib/schemas';
import { authApi } from '../services/authApi';
import { useAuthStore } from '../store/authStore';

export default function Login() {
  const user = useAuthStore((s) => s.user);
  const navigate = useNavigate();
  const location = useLocation();
  const [error, setError] = useState('');
  const turnstile = useTurnstile('login');
  const { register, handleSubmit, formState: { errors, isSubmitting } } = useForm<LoginForm>({ resolver: zodResolver(loginSchema) });

  if (user) return <Navigate to="/dashboard" replace />;
  const from = (location.state as { from?: { pathname: string } } | null)?.from?.pathname ?? '/dashboard';

  const onSubmit = handleSubmit(async ({ email, password }) => {
    setError('');
    try {
      await authApi.login(email, password, turnstile.token);
      navigate(from, { replace: true });
    } catch (e) {
      setError(getErrorMessage(e));
      turnstile.reset(); // a Turnstile token is single-use, even when the password was wrong
    }
  });

  return (
    <AuthLayout title="Sign in" subtitle="Use your SecureShare ZT account.">
      <form onSubmit={onSubmit} className="space-y-4" noValidate>
        {error && <Alert kind="error">{error}</Alert>}
        <Field label="Email" type="email" autoComplete="email" error={errors.email?.message} {...register('email')} />
        <Field label="Password" type="password" autoComplete="current-password" error={errors.password?.message} {...register('password')} />
        {turnstile.widget}
        <Button type="submit" loading={isSubmitting} disabled={!turnstile.ready} className="w-full">Sign in</Button>
      </form>
      <div className="mt-6 flex justify-between text-sm text-mute">
        <Link to="/forgot-password" className="hover:text-fog">Forgot password?</Link>
        <Link to="/register" className="hover:text-fog">Create account</Link>
      </div>
    </AuthLayout>
  );
}
