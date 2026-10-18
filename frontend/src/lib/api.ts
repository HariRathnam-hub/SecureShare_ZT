import axios, { AxiosError, InternalAxiosRequestConfig } from 'axios';
import { useAuthStore } from '../store/authStore';

const baseURL = import.meta.env.VITE_API_URL || '/api/v1';
const CSRF = { 'X-Requested-With': 'XMLHttpRequest' };

export const api = axios.create({ baseURL, withCredentials: true, timeout: 15_000, headers: CSRF });

api.interceptors.request.use((cfg) => {
  const token = useAuthStore.getState().accessToken;
  if (token) cfg.headers.Authorization = `Bearer ${token}`;
  return cfg;
});

// Single-flight: concurrent callers (StrictMode, parallel 401s) share one refresh.
// Required because refresh tokens are single-use and reuse revokes the session.
let inflight: Promise<string> | null = null;
export function refreshSession(): Promise<string> {
  inflight ??= axios
    .post(`${baseURL}/auth/refresh`, null, { withCredentials: true, headers: CSRF })
    .then((res) => {
      const { user, accessToken } = res.data.data;
      useAuthStore.getState().setSession(user, accessToken);
      return accessToken as string;
    })
    .finally(() => {
      inflight = null;
    });
  return inflight;
}

api.interceptors.response.use(
  (res) => res,
  async (error: AxiosError) => {
    const original = error.config as (InternalAxiosRequestConfig & { _retry?: boolean }) | undefined;
    const isAuthRoute = original?.url?.startsWith('/auth/');
    if (error.response?.status === 401 && original && !original._retry && !isAuthRoute) {
      original._retry = true;
      try {
        const token = await refreshSession();
        original.headers.Authorization = `Bearer ${token}`;
        return api(original);
      } catch {
        useAuthStore.getState().clearSession();
      }
    }
    return Promise.reject(error);
  },
);

export function getErrorMessage(err: unknown): string {
  if (axios.isAxiosError(err)) {
    if (!err.response) return 'Cannot reach the server. Check your connection and try again.';
    const data = (err.response.data ?? {}) as { message?: string; errors?: Record<string, string[]>; retryAfterSeconds?: number };
    const first = data.errors && Object.values(data.errors)[0]?.[0];
    if (err.response.status === 429) {
      const secs = data.retryAfterSeconds ?? Number(err.response.headers?.['retry-after']);
      const wait = Number.isFinite(secs) && secs > 0 ? (secs >= 90 ? `${Math.ceil(secs / 60)} minutes` : `${Math.ceil(secs)} seconds`) : '';
      return `${data.message ?? 'Too many requests.'}${wait ? ` Try again in about ${wait}.` : ''}`;
    }
    return first ?? data.message ?? 'Something went wrong.';
  }
  return 'Something went wrong.';
}
