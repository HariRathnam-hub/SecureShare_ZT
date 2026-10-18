import assert from 'assert';
import os from 'os';
import path from 'path';
import { installFakeDb } from './helpers/fake-db';
import { serve } from './helpers/http';

// Production mode: CORS lock-down, secure cookies, Turnstile on every form, rate limits on the real routes.
process.env.DOTENV_CONFIG_PATH = path.join(os.tmpdir(), 'szt-no-such.env');
Object.assign(process.env, {
  NODE_ENV: 'production', MONGODB_URI: 'mongodb://localhost/x', CLIENT_URL: 'https://secureshare-zt.pages.dev',
  JWT_ACCESS_SECRET: 'a'.repeat(40), JWT_REFRESH_SECRET: 'b'.repeat(40), BREVO_API_KEY: 'k', EMAIL_FROM_ADDRESS: 'a@example.com',
  TURNSTILE_SECRET_KEY: '0x4AAAAAAA-test-secret-value-not-real', UPLOAD_DIR: path.join(os.tmpdir(), 'szt-ph'),
});
delete process.env.ALLOWED_ORIGINS;
const ORIGIN = 'https://secureshare-zt.pages.dev';

(async () => {
  const siteverify: string[] = [];
  (globalThis as any).fetch = async (url: string, init: any) => {
    if (String(url).includes('siteverify')) {
      siteverify.push(init.body.get('response'));
      const tokenOk = !String(init.body.get('response')).startsWith('bad');
      const action = String(init.body.get('response')).split(':')[1] ?? 'login';
      return { ok: true, status: 200, json: async () => (tokenOk ? { success: true, hostname: 'secureshare-zt.pages.dev', action } : { success: false, 'error-codes': ['invalid-input-response'] }) };
    }
    return { ok: true, status: 200, text: async () => '' }; // Brevo
  };
  const { User } = await import('../src/modules/user/user.model');
  const { AuditLog } = await import('../src/modules/audit/audit-log.model');
  const { app } = await import('../src/app');
  const db = installFakeDb({ User, AuditLog });
  db.makeUser({ email: 'ann@example.com', password: 'Correct-Horse-9!' });
  const s = serve(app);
  let n = 0;
  const token = (action: string) => `tok${++n}:${action}`;
  const post = (p: string, body: object, headers: object = {}) => s.call('POST', `/api/v1/auth${p}`, { body, headers: { origin: ORIGIN, ...headers } });
  const login = (pw = 'Correct-Horse-9!', t = token('login'), email = 'ann@example.com') => post('/login', { email, password: pw, turnstileToken: t });

  // ---- CORS: only the Pages origin ----
  let r = await s.call('GET', '/health', { headers: { origin: ORIGIN } });
  assert.equal(r.headers['access-control-allow-origin'], ORIGIN); assert.equal(r.headers['access-control-allow-credentials'], 'true');
  assert(String(r.headers['access-control-expose-headers']).includes('Retry-After'));
  assert(r.headers['strict-transport-security'], 'HSTS in production');
  for (const bad of ['https://evil.example', 'http://localhost:5173', 'http://127.0.0.1:5173', 'https://secureshare-zt.pages.dev.evil.com', 'http://secureshare-zt.pages.dev', 'https://preview.secureshare-zt.pages.dev', 'null', 'https://secureshare-zt.onrender.com']) {
    r = await s.call('GET', '/health', { headers: { origin: bad } });
    assert.equal(r.status, 403, bad); assert(!r.headers['access-control-allow-origin'], bad);
    r = await s.call('OPTIONS', '/api/v1/auth/login', { headers: { origin: bad, 'access-control-request-method': 'POST' } });
    assert.equal(r.status, 403, `preflight ${bad}`);
  }
  r = await s.call('OPTIONS', '/api/v1/auth/login', { headers: { origin: ORIGIN, 'access-control-request-method': 'POST', 'access-control-request-headers': 'content-type,x-requested-with' } });
  assert.equal(r.status, 204); assert.equal(r.headers['access-control-allow-origin'], ORIGIN);
  assert(!String(r.headers['access-control-allow-methods']).includes('PUT'));

  // ---- Turnstile enforced on login / register / forgot / reset ----
  const before = siteverify.length;
  assert.equal((await post('/login', { email: 'ann@example.com', password: 'Correct-Horse-9!' })).json.code, 'TURNSTILE_REQUIRED');
  assert.equal((await post('/register', { name: 'Zed', email: 'zed@example.com', password: 'Str0ng-Passw0rd!' })).json.code, 'TURNSTILE_REQUIRED');
  assert.equal((await post('/forgot-password', { email: 'ann@example.com' })).json.code, 'TURNSTILE_REQUIRED');
  assert.equal((await post('/reset-password', { token: 'a'.repeat(64), password: 'Str0ng-Passw0rd!' })).json.code, 'TURNSTILE_REQUIRED');
  assert.equal(siteverify.length, before, 'no Cloudflare call without a token');
  assert(!db.users.some((u) => u.email === 'zed@example.com'), 'blocked registration created nothing');
  assert.equal((await post('/login', { email: 'ann@example.com', password: 'Correct-Horse-9!', turnstileToken: 'bad-1:login' })).json.code, 'TURNSTILE_FAILED');
  assert.equal((await login('Correct-Horse-9!', token('register'))).status, 400, 'register-form token rejected on login');
  assert.equal((await post('/register', { name: 'Zed', email: 'zed@example.com', password: 'Str0ng-Passw0rd!', turnstileToken: token('register') })).status, 201);
  assert.equal((await post('/forgot-password', { email: 'ann@example.com', turnstileToken: token('forgot-password') })).status, 200);
  r = await post('/reset-password', { token: 'a'.repeat(64), password: 'Str0ng-Passw0rd!', turnstileToken: token('reset-password') });
  assert.equal(r.status, 400); assert.match(r.json.message, /invalid or has expired/, 'valid challenge reaches the real handler');

  // ---- secure cookie + rotation still work behind Turnstile ----
  r = await login();
  assert.equal(r.status, 200);
  const cookie = ([] as string[]).concat(r.headers['set-cookie']!).find((c) => c.startsWith('szt_rt='))!;
  assert(/;\s*Secure/i.test(cookie) && /HttpOnly/i.test(cookie) && /SameSite=None/i.test(cookie) && /Path=\/api\/v1\/auth/.test(cookie), cookie);
  const rr = await s.call('POST', '/api/v1/auth/refresh', { headers: { origin: ORIGIN, 'x-requested-with': 'XMLHttpRequest', cookie: cookie.split(';')[0] } });
  assert.equal(rr.status, 200, 'refresh needs no Turnstile (cookie + CSRF header protected)');
  assert.notEqual(([] as string[]).concat(rr.headers['set-cookie']!)[0].split(';')[0], cookie.split(';')[0]);

  // ---- rate limits on the real route: per account+IP after 8 attempts -> 429 + Retry-After ----
  let last: any;
  for (let i = 0; i < 9; i++) last = await login('wrong-password');
  assert.equal(last.status, 429, 'brute force is throttled'); assert(Number(last.headers['retry-after']) > 0);
  assert.equal(last.json.code, 'RATE_LIMITED');
  assert.equal((await login('Correct-Horse-9!', token('login'), 'other@example.com')).status, 401, 'other accounts from the same IP are not locked by this bucket');
  r = await s.call('GET', '/health');
  assert.equal(r.status, 200, '/health is never throttled');

  s.close();
  console.log('production: CORS lock-down, secure cookies, Turnstile on all forms, 429s: OK');
  process.exit(0);
})().catch((e) => { console.error(e); process.exit(1); });
