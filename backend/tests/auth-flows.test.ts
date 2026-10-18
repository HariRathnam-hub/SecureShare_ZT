import assert from 'assert';
import os from 'os';
import path from 'path';
import { installFakeDb } from './helpers/fake-db';
import { serve } from './helpers/http';

// Development mode, Turnstile NOT configured: existing auth behaviour must be unchanged.
process.env.DOTENV_CONFIG_PATH = path.join(os.tmpdir(), 'szt-no-such.env');
Object.assign(process.env, {
  NODE_ENV: 'development', MONGODB_URI: 'mongodb://localhost/x', CLIENT_URL: 'http://localhost:5173',
  JWT_ACCESS_SECRET: 'a'.repeat(40), JWT_REFRESH_SECRET: 'b'.repeat(40), UPLOAD_DIR: path.join(os.tmpdir(), 'szt-af'),
});
delete process.env.TURNSTILE_SECRET_KEY;

const cookieOf = (set: string | string[] | undefined) => { const c = ([] as string[]).concat(set ?? []).find((x) => x.startsWith('szt_rt=')); return c; };
const rt = (c?: string) => c!.split(';')[0].slice('szt_rt='.length);

(async () => {
  const { User } = await import('../src/modules/user/user.model');
  const { AuditLog } = await import('../src/modules/audit/audit-log.model');
  const { app } = await import('../src/app');
  const db = installFakeDb({ User, AuditLog });
  const u = db.makeUser({ email: 'ann@example.com', password: 'Correct-Horse-9!', verified: true });
  db.makeUser({ email: 'unverified@example.com', password: 'Correct-Horse-9!', verified: false });
  const s = serve(app);
  const login = (email: string, password: string) => s.call('POST', '/api/v1/auth/login', { body: { email, password } });
  const xhr = { 'x-requested-with': 'XMLHttpRequest' };

  // login
  let r = await login('ann@example.com', 'Correct-Horse-9!');
  assert.equal(r.status, 200); assert(r.json.data.accessToken);
  let c = cookieOf(r.headers['set-cookie'])!;
  assert(!r.body.includes(rt(c)) && !r.body.includes('Correct-Horse'), 'refresh token only travels in the HttpOnly cookie');
  assert(/HttpOnly/i.test(c) && /SameSite=Lax/i.test(c) && /Path=\/api\/v1\/auth/.test(c) && !/Secure/i.test(c), 'dev cookie flags: ' + c);
  assert.equal(r.headers['cache-control'], 'no-store');
  const access = r.json.data.accessToken;
  assert.equal((await s.call('GET', '/api/v1/users/me', { headers: { authorization: `Bearer ${access}` } })).status, 200, 'access token authenticates');

  // failures: identical answer for wrong password and unknown account, both audited, unverified refused
  const bad = await login('ann@example.com', 'nope'); const unk = await login('ghost@example.com', 'nope');
  assert.equal(bad.status, 401); assert.equal(unk.status, 401); assert.equal(bad.json.message, unk.json.message);
  assert(db.audits.filter((a) => a.action === 'LOGIN_FAILED').length >= 2);
  assert.equal((await login('unverified@example.com', 'Correct-Horse-9!')).status, 403);

  // refresh needs the CSRF header; rotation issues a new token; the old one is dead and its reuse revokes every session
  assert.equal((await s.call('POST', '/api/v1/auth/refresh', { headers: { cookie: `szt_rt=${rt(c)}` } })).status, 403, 'missing X-Requested-With');
  r = await s.call('POST', '/api/v1/auth/refresh', { headers: { ...xhr, cookie: `szt_rt=${rt(c)}` } });
  assert.equal(r.status, 200);
  const c2 = cookieOf(r.headers['set-cookie'])!;
  assert.notEqual(rt(c2), rt(c), 'refresh token rotated');
  r = await s.call('POST', '/api/v1/auth/refresh', { headers: { ...xhr, cookie: `szt_rt=${rt(c)}` } });
  assert.equal(r.status, 401, 'reused (already rotated) token rejected');
  assert(db.audits.some((a) => a.action === 'SESSION_REVOKED' && a.metadata.reason === 'refresh_token_reuse'));
  assert.equal(u.refreshTokens.length, 0, 'theft response: all sessions revoked');
  assert.equal((await s.call('POST', '/api/v1/auth/refresh', { headers: { ...xhr, cookie: `szt_rt=${rt(c2)}` } })).status, 401, 'even the newest token is revoked');
  assert.equal((await s.call('POST', '/api/v1/auth/refresh', { headers: xhr })).status, 401, 'no cookie');
  assert.equal((await s.call('POST', '/api/v1/auth/refresh', { headers: { ...xhr, cookie: 'szt_rt=forged.jwt.value' } })).status, 401);

  // logout revokes the presented refresh token
  c = cookieOf((await login('ann@example.com', 'Correct-Horse-9!')).headers['set-cookie'])!;
  r = await s.call('POST', '/api/v1/auth/logout', { headers: { ...xhr, cookie: `szt_rt=${rt(c)}` } });
  assert.equal(r.status, 204);
  assert.equal((await s.call('POST', '/api/v1/auth/refresh', { headers: { ...xhr, cookie: `szt_rt=${rt(c)}` } })).status, 401);

  // anti-enumeration is unchanged
  const a1 = await s.call('POST', '/api/v1/auth/forgot-password', { body: { email: 'ann@example.com' } });
  const a2 = await s.call('POST', '/api/v1/auth/forgot-password', { body: { email: 'nobody@example.com' } });
  assert.equal(a1.status, 200); assert.equal(a1.body, a2.body);
  const g1 = await s.call('POST', '/api/v1/auth/register', { body: { name: 'Ann', email: 'ann@example.com', password: 'Str0ng-Passw0rd!' } });
  const g2 = await s.call('POST', '/api/v1/auth/register', { body: { name: 'New', email: 'new@example.com', password: 'Str0ng-Passw0rd!' } });
  assert.equal(g1.status, 201); assert.equal(g1.body, g2.body, 'existing and new email look identical');
  // validation still strips unknown keys (a client cannot smuggle role/isActive into registration)
  assert.equal(db.users.find((x) => x.email === 'new@example.com')!.role, 'user');

  s.close();
  console.log('existing auth flows (login, rotation, reuse revocation, logout, anti-enumeration): OK');
  process.exit(0);
})().catch((e) => { console.error(e); process.exit(1); });
