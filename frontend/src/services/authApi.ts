import { api } from '../lib/api';
import { useAuthStore, User } from '../store/authStore';

export const authApi = {
  async login(email: string, password: string, turnstileToken?: string) {
    const { data } = await api.post('/auth/login', { email, password, turnstileToken });
    useAuthStore.getState().setSession(data.data.user, data.data.accessToken);
  },
  register: (name: string, email: string, password: string, turnstileToken?: string) =>
    api.post('/auth/register', { name, email, password, turnstileToken }),
  verifyEmail: (token: string) => api.post('/auth/verify-email', { token }),
  forgotPassword: (email: string, turnstileToken?: string) => api.post('/auth/forgot-password', { email, turnstileToken }),
  resetPassword: (token: string, password: string, turnstileToken?: string) =>
    api.post('/auth/reset-password', { token, password, turnstileToken }),
  async logout() {
    try {
      await api.post('/auth/logout');
    } finally {
      useAuthStore.getState().clearSession();
    }
  },
};

export const userApi = {
  list: async (page = 1) =>
    (await api.get<{ data: { users: User[]; total: number } }>('/users', { params: { page } })).data.data,
  setRole: (id: string, role: 'user' | 'admin') => api.patch(`/users/${id}/role`, { role }),
};
