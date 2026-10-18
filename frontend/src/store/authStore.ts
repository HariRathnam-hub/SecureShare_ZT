import { create } from 'zustand';

export type Role = 'user' | 'admin';
export interface User {
  id: string;
  name: string;
  email: string;
  role: Role;
  isEmailVerified: boolean;
  createdAt: string;
}

interface AuthState {
  user: User | null;
  /** Held in memory only: never written to localStorage/sessionStorage. */
  accessToken: string | null;
  isInitializing: boolean;
  setSession: (user: User, accessToken: string) => void;
  clearSession: () => void;
  finishInit: () => void;
}

export const useAuthStore = create<AuthState>((set) => ({
  user: null,
  accessToken: null,
  isInitializing: true,
  setSession: (user, accessToken) => set({ user, accessToken }),
  clearSession: () => set({ user: null, accessToken: null }),
  finishInit: () => set({ isInitializing: false }),
}));
