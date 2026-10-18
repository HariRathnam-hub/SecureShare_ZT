import { zodResolver } from '@hookform/resolvers/zod';
import { useState } from 'react';
import { useForm } from 'react-hook-form';
import { Link, useSearchParams } from 'react-router-dom';
import { Alert, Button, Field } from '../components/ui';
import AuthLayout from '../layouts/AuthLayout';
import { getErrorMessage } from '../lib/api';
import { useTurnstile } from '../components/Turnstile';
import { ResetForm, resetSchema } from '../lib/schemas';
import { authApi } from '../services/authApi';

export default function ResetPassword() {
  const [params] = useSearchParams();
  const token = params.get('token') ?? '';
  const [error, setError] = useState('');
  const [done, setDone] = useState(false);
  const turnstile = useTurnstile('reset-password');
  const { register, handleSubmit, formState: { errors, isSubmitting } } = useForm<ResetForm>({ resolver: zodResolver(resetSchema) });

  const onSubmit = handleSubmit(async ({ password }) => {
    setError('');
    try {
      await authApi.resetPassword(token, password, turnstile.token);
      setDone(true);
    } catch (e) {
      setError(getErrorMessage(e));
      turnstile.reset();
    }
  });

  return (
    <AuthLayout title="Choose a new password" subtitle="All your other sessions will be signed out.">
      {!token ? (
        <Alert kind="error">This reset link is missing its token. Request a new one.</Alert>
      ) : done ? (
        <Alert kind="success">Password updated. You can sign in now.</Alert>
      ) : (
        <form onSubmit={onSubmit} className="space-y-4" noValidate>
          {error && <Alert kind="error">{error}</Alert>}
          <Field label="New password" type="password" autoComplete="new-password" error={errors.password?.message} {...register('password')} />
          <Field label="Confirm password" type="password" autoComplete="new-password" error={errors.confirmPassword?.message} {...register('confirmPassword')} />
          {turnstile.widget}
          <Button type="submit" loading={isSubmitting} disabled={!turnstile.ready} className="w-full">Update password</Button>
        </form>
      )}
      <Link to="/login" className="mt-6 inline-block text-sm text-mute hover:text-fog">Go to sign in</Link>
    </AuthLayout>
  );
}
