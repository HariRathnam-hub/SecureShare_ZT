import { zodResolver } from '@hookform/resolvers/zod';
import { useState } from 'react';
import { useForm } from 'react-hook-form';
import { Link } from 'react-router-dom';
import { Alert, Button, Field } from '../components/ui';
import AuthLayout from '../layouts/AuthLayout';
import { getErrorMessage } from '../lib/api';
import { useTurnstile } from '../components/Turnstile';
import { ForgotForm, forgotSchema } from '../lib/schemas';
import { authApi } from '../services/authApi';

export default function ForgotPassword() {
  const [error, setError] = useState('');
  const [done, setDone] = useState(false);
  const turnstile = useTurnstile('forgot-password');
  const { register, handleSubmit, formState: { errors, isSubmitting } } = useForm<ForgotForm>({ resolver: zodResolver(forgotSchema) });

  const onSubmit = handleSubmit(async ({ email }) => {
    setError('');
    try {
      await authApi.forgotPassword(email, turnstile.token);
      setDone(true);
    } catch (e) {
      setError(getErrorMessage(e));
      turnstile.reset();
    }
  });

  return (
    <AuthLayout title="Reset your password" subtitle="We'll email a link that works for one hour.">
      {done ? (
        <Alert kind="success">If an account exists for that email, a reset link has been sent.</Alert>
      ) : (
        <form onSubmit={onSubmit} className="space-y-4" noValidate>
          {error && <Alert kind="error">{error}</Alert>}
          <Field label="Email" type="email" autoComplete="email" error={errors.email?.message} {...register('email')} />
          {turnstile.widget}
          <Button type="submit" loading={isSubmitting} disabled={!turnstile.ready} className="w-full">Send reset link</Button>
        </form>
      )}
      <Link to="/login" className="mt-6 inline-block text-sm text-mute hover:text-fog">Back to sign in</Link>
    </AuthLayout>
  );
}
