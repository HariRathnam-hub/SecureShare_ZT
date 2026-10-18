import { ButtonHTMLAttributes, forwardRef, InputHTMLAttributes, ReactNode } from 'react';

type InputProps = InputHTMLAttributes<HTMLInputElement> & { label: string; error?: string };

export const Field = forwardRef<HTMLInputElement, InputProps>(({ label, error, id, ...rest }, ref) => {
  const fieldId = id ?? rest.name;
  return (
    <div>
      <label htmlFor={fieldId} className="mb-1.5 block text-sm font-medium text-fog">
        {label}
      </label>
      <input
        ref={ref}
        id={fieldId}
        aria-invalid={!!error}
        aria-describedby={error ? `${fieldId}-err` : undefined}
        className="w-full rounded-md border border-line bg-ink px-3 py-2.5 text-sm text-fog placeholder:text-mute/60 focus:border-signal"
        {...rest}
      />
      {error && (
        <p id={`${fieldId}-err`} className="mt-1.5 text-sm text-danger">
          {error}
        </p>
      )}
    </div>
  );
});
Field.displayName = 'Field';

export function Button({
  loading,
  variant = 'primary',
  children,
  className = '',
  ...rest
}: ButtonHTMLAttributes<HTMLButtonElement> & { loading?: boolean; variant?: 'primary' | 'ghost' }) {
  const styles =
    variant === 'primary'
      ? 'bg-signal text-ink hover:bg-signal/90'
      : 'border border-line text-fog hover:bg-panel';
  return (
    <button
      disabled={loading || rest.disabled}
      className={`inline-flex items-center justify-center rounded-md px-4 py-2.5 text-sm font-semibold transition-colors disabled:cursor-not-allowed disabled:opacity-60 ${styles} ${className}`}
      {...rest}
    >
      {loading ? 'Working…' : children}
    </button>
  );
}

export function Alert({ kind, children }: { kind: 'error' | 'success'; children: ReactNode }) {
  const color = kind === 'error' ? 'border-danger/50 text-danger' : 'border-signal/50 text-signal';
  return (
    <div role={kind === 'error' ? 'alert' : 'status'} className={`rounded-md border bg-panel px-3 py-2.5 text-sm ${color}`}>
      {children}
    </div>
  );
}
