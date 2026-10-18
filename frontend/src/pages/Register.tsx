import { zodResolver } from '@hookform/resolvers/zod';
import { useState } from 'react';
import { useForm } from 'react-hook-form';
import { Link } from 'react-router-dom';
import { Alert, Button, Field } from '../components/ui';
import AuthLayout from '../layouts/AuthLayout';
import { getErrorMessage } from '../lib/api';
import { useTurnstile } from '../components/Turnstile';
import { RegisterForm, registerSchema } from '../lib/schemas';
import { authApi } from '../services/authApi';

export default function Register() {
  const [error, setError] = useState('');
  const [done, setDone] = useState(false);
  const turnstile = useTurnstile('register');
  const { register, handleSubmit, formState: { errors, isSubmitting } } = useForm<RegisterForm>({ resolver: zodResolver(registerSchema) });

  const onSubmit = handleSubmit(async ({ name, email, password }) => {
    setError('');
    try {
      await authApi.register(name, email, password, turnstile.token);
      setDone(true);
    } catch (e) {
      setError(getErrorMessage(e));
      turnstile.reset();
    }
  });

  if (done)
    return (
      <AuthLayout title="Check your email">
        <Alert kind="success">If this email can be registered, a verification link is on its way. It expires in 24 hours.</Alert>
        <Link to="/login" className="mt-6 inline-block text-sm text-mute hover:text-fog">Back to sign in</Link>
      </AuthLayout>
    );

  return (
    <AuthLayout title="Create your account" subtitle="Passwords need 10+ characters with upper, lower, number and symbol.">
      <form onSubmit={onSubmit} className="space-y-4" noValidate>
        {error && <Alert kind="error">{error}</Alert>}
        <Field label="Name" autoComplete="name" error={errors.name?.message} {...register('name')} />
        <Field label="Email" type="email" autoComplete="email" error={errors.email?.message} {...register('email')} />
        <Field label="Password" type="password" autoComplete="new-password" error={errors.password?.message} {...register('password')} />
        <Field label="Confirm password" type="password" autoComplete="new-password" error={errors.confirmPassword?.message} {...register('confirmPassword')} />
        {turnstile.widget}
        <Button type="submit" loading={isSubmitting} disabled={!turnstile.ready} className="w-full">Create account</Button>
      </form>
      <p className="mt-6 text-sm text-mute">
        Already registered? <Link to="/login" className="text-fog hover:underline">Sign in</Link>
      </p>
    </AuthLayout>
  );
}
