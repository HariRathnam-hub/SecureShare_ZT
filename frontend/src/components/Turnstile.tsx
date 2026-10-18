import { forwardRef, useEffect, useImperativeHandle, useRef, useState } from 'react';
import { Alert } from './ui';

export type TurnstileAction = 'login' | 'register' | 'forgot-password' | 'reset-password';

interface TurnstileApi {
  render(el: HTMLElement, opts: Record<string, unknown>): string;
  reset(id?: string): void;
  remove(id?: string): void;
}
declare global {
  interface Window {
    turnstile?: TurnstileApi;
  }
}

/** Public site key (safe to ship). The matching SECRET key lives only on the API server. */
const SITE_KEY = String(import.meta.env.VITE_TURNSTILE_SITE_KEY ?? '').trim();
export const turnstileConfigured = SITE_KEY.length > 0;
/** Production builds fail closed: no site key means forms cannot be submitted (the API would reject them anyway). */
export const turnstileRequired = import.meta.env.PROD === true;

const SCRIPT_SRC = 'https://challenges.cloudflare.com/turnstile/v0/api.js?render=explicit';
let scriptPromise: Promise<void> | null = null;
function loadScript(): Promise<void> {
  if (window.turnstile) return Promise.resolve();
  scriptPromise ??= new Promise<void>((resolve, reject) => {
    const s = document.createElement('script');
    s.src = SCRIPT_SRC;
    s.async = true;
    s.defer = true;
    s.onload = () => resolve();
    s.onerror = () => {
      scriptPromise = null; // allow a retry on the next mount
      reject(new Error('Turnstile script failed to load'));
    };
    document.head.appendChild(s);
  });
  return scriptPromise;
}

export interface TurnstileHandle {
  reset(): void;
}

/** Cloudflare Turnstile (Managed mode: Cloudflare decides whether any interaction is needed). */
export const TurnstileWidget = forwardRef<TurnstileHandle, { action: TurnstileAction; onToken: (token: string | null) => void }>(
  ({ action, onToken }, ref) => {
    const box = useRef<HTMLDivElement>(null);
    const widgetId = useRef<string>();
    const [loadError, setLoadError] = useState(false);
    const onTokenRef = useRef(onToken);
    onTokenRef.current = onToken;

    useImperativeHandle(ref, () => ({
      reset() {
        onTokenRef.current(null);
        if (widgetId.current && window.turnstile) window.turnstile.reset(widgetId.current);
      },
    }));

    useEffect(() => {
      if (!turnstileConfigured) return;
      let cancelled = false;
      loadScript()
        .then(() => {
          if (cancelled || !box.current || !window.turnstile) return;
          widgetId.current = window.turnstile.render(box.current, {
            sitekey: SITE_KEY,
            action, // bound to this form; the API rejects a token minted for another action
            theme: 'auto',
            callback: (t: string) => onTokenRef.current(t),
            'expired-callback': () => onTokenRef.current(null), // tokens last 5 minutes and are single-use
            'error-callback': () => onTokenRef.current(null),
            'timeout-callback': () => onTokenRef.current(null),
          });
        })
        .catch(() => !cancelled && setLoadError(true));
      return () => {
        cancelled = true;
        if (widgetId.current && window.turnstile) window.turnstile.remove(widgetId.current);
        widgetId.current = undefined;
      };
    }, [action]);

    if (!turnstileConfigured) {
      return turnstileRequired ? <Alert kind="error">The security check is not configured for this site. Please contact the administrator.</Alert> : null;
    }
    return (
      <div>
        <div ref={box} />
        {loadError && <Alert kind="error">The security check could not load. Disable content blockers for this site and refresh the page.</Alert>}
      </div>
    );
  },
);
TurnstileWidget.displayName = 'TurnstileWidget';

/** Wires a widget into a form: render `widget`, disable submit until `ready`, call `reset()` after every attempt (tokens are single-use). */
export function useTurnstile(action: TurnstileAction) {
  const [token, setToken] = useState<string | null>(null);
  const handle = useRef<TurnstileHandle>(null);
  const blocked = turnstileRequired && !turnstileConfigured;
  const ready = !blocked && (!turnstileConfigured || token !== null);
  return {
    token: token ?? undefined,
    ready,
    reset: () => handle.current?.reset(),
    widget: <TurnstileWidget ref={handle} action={action} onToken={setToken} />,
  };
}
