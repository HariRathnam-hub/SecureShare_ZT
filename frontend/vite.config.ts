import react from '@vitejs/plugin-react';
import { defineConfig } from 'vite';

// The browser only ever talks to this origin; /api is proxied to the backend, so the refresh cookie stays
// same-origin and backend ports/secrets are never exposed. This is also what makes a single Cloudflare Quick Tunnel
// (pointed at the frontend port) enough to reach the whole app.
const proxy = { '/api': { target: 'http://localhost:5000', changeOrigin: false, xfwd: true } };

// Vite blocks unknown Host headers. Allow Cloudflare Quick Tunnel hostnames (and a named tunnel hostname if you set one).
// Add your own hostname with: VITE_ALLOWED_HOST=app.example.com
const env = (globalThis as { process?: { env?: Record<string, string | undefined> } }).process?.env ?? {};
const allowedHosts = ['.trycloudflare.com', ...(env.VITE_ALLOWED_HOST ? [env.VITE_ALLOWED_HOST] : [])];

export default defineConfig({
  plugins: [react()],
  server: { port: 5173, proxy, allowedHosts },
  preview: { port: 5173, proxy, allowedHosts },
});
