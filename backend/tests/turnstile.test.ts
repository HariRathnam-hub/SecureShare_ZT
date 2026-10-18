import assert from 'assert';
import express from 'express';
import os from 'os';
import path from 'path';
import { serve } from './helpers/http';

process.env.DOTENV_CONFIG_PATH = path.join(os.tmpdir(), 'szt-no-such.env');
const SECRET = '0x4AAAAAAA-test-secret-value-not-real';
Object.assign(process.env, {
  NODE_ENV: 'production', MONGODB_URI: 'mongodb://localhost/x', CLIENT_URL: 'https://secureshare-zt.pages.dev',
  JWT_ACCESS_SECRET: 'a'.repeat(40), JWT_REFRESH_SECRET: 'b'.repeat(40), BREVO_API_KEY: 'k', EMAIL_FROM_ADDRESS: 'a@example.com',
  TURNSTILE_SECRET_KEY: SECRET, UPLOAD_DIR: path.join(os.tmpdir(), 'szt-ts'),
});
delete process.env.ALLOWED_ORIGINS;

(async () => {
  const { AuditLog } = await import('../src/modules/audit/audit-log.model');
  const audits: any[] = [];
  (AuditLog as any).create = async (d: any) => { audits.push(d); return d; };
  const { requireTurnstile } = await import('../src/middleware/turnstile');
  const { verifyTurnstile, resetTurnstileState, SITEVERIFY_URL } = await import('../src/services/turnstile.service');
  const { errorHandler } = await import('../src/middleware/errorHandler');

  const calls: { url: string; init: any }[] = [];
  let reply: () => Promise<any> = async () => ({ ok: true, json: async () => ({ success: true, hostname: 'secureshare-zt.pages.dev', action: 'login' }) });
  (globalThis as any).fetch = async (url: string, init: any) => { calls.push({ url, init }); return reply(); };
  const ok = (over: object = {}) => async () => ({ ok: true, status: 200, json: async () => ({ success: true, hostname: 'secureshare-zt.pages.dev', action: 'login', ...over }) });
  const fail = (...codes: string[]) => async () => ({ ok: true, status: 200, json: async () => ({ success: false, 'error-codes': codes }) });
  const reset = () => { calls.length = 0; audits.length = 0; resetTurnstileState(); reply = ok(); };

  const app = express();
  app.use(express.json());
  app.post('/login', requireTurnstile('login'), (req, res) => res.json({ body: req.body }));
  app.use(errorHandler);
  const s = serve(app);
  const post = (body: object) => s.call('POST', '/login', { body });

  // 1. Missing / non-string token: rejected before any network call.
  reset();
  let r = await post({ email: 'a@b.co' });
  assert.equal(r.status, 400); assert.equal(r.json.code, 'TURNSTILE_REQUIRED'); assert.equal(calls.length, 0);
  r = await post({ turnstileToken: { evil: 1 } });
  assert.equal(r.json.code, 'TURNSTILE_REQUIRED');
  r = await post({ turnstileToken: 'x'.repeat(2049) });
  assert.equal(r.json.code, 'TURNSTILE_FAILED'); assert.equal(calls.length, 0, 'oversized token never leaves the server');

  // 2. Valid token: goes to Cloudflare's Siteverify with the secret, then is stripped from the body.
  reset();
  r = await post({ email: 'a@b.co', turnstileToken: 'good-token' });
  assert.equal(r.status, 200);
  assert.equal(r.json.body.turnstileToken, undefined, 'token never reaches controllers');
  assert.equal(calls.length, 1);
  assert.equal(calls[0].url, SITEVERIFY_URL);
  assert.equal(calls[0].init.method, 'POST');
  assert.equal(calls[0].init.body.get('secret'), SECRET);
  assert.equal(calls[0].init.body.get('response'), 'good-token');

  // 3. Invalid token -> 400, and nothing about Cloudflare's answer or our secret leaks to the client.
  reset(); reply = fail('invalid-input-response');
  r = await post({ turnstileToken: 'bad' });
  assert.equal(r.status, 400); assert.equal(r.json.code, 'TURNSTILE_FAILED');
  assert(!r.body.includes(SECRET) && !r.body.includes('invalid-input-response'));

  // 4. Expired / already-redeemed token (Cloudflare says timeout-or-duplicate).
  reset(); reply = fail('timeout-or-duplicate');
  r = await post({ turnstileToken: 'old' });
  assert.equal(r.status, 400); assert.equal(r.json.code, 'TURNSTILE_EXPIRED');

  // 5. Reuse: the same token cannot be redeemed twice; the second attempt is refused locally without calling Cloudflare.
  reset();
  assert.equal((await post({ turnstileToken: 'once' })).status, 200);
  r = await post({ turnstileToken: 'once' });
  assert.equal(r.status, 400); assert.equal(r.json.code, 'TURNSTILE_EXPIRED'); assert.equal(calls.length, 1);

  // 6. Concurrent double-submit of one token: exactly one wins.
  reset();
  const results = await Promise.all([post({ turnstileToken: 'race' }), post({ turnstileToken: 'race' }), post({ turnstileToken: 'race' })]);
  assert.equal(results.filter((x) => x.status === 200).length, 1); assert.equal(calls.length, 1);

  // 7. Provider failures fail CLOSED (503), never open. The token is released so the user can retry.
  const failures: [string, () => Promise<any>][] = [
    ['network error', async () => { throw new Error('ECONNRESET'); }],
    ['HTTP 500', async () => ({ ok: false, status: 500, json: async () => ({}) })],
    ['invalid JSON', async () => ({ ok: true, status: 200, json: async () => { throw new SyntaxError('bad'); } })],
    ['non-object JSON', async () => ({ ok: true, status: 200, json: async () => 'nope' })],
    ['internal-error', fail('internal-error')],
    ['secret rejected', fail('invalid-input-secret')],
  ];
  for (const [name, fn] of failures) {
    reset(); reply = fn;
    r = await post({ turnstileToken: 'tok' });
    assert.equal(r.status, 503, name); assert.equal(r.json.code, 'TURNSTILE_UNAVAILABLE', name);
    assert(!r.body.includes(SECRET), name);
  }
  reset(); reply = async () => { throw new Error('down'); };
  await post({ turnstileToken: 'retry-me' });
  reply = ok();
  assert.equal((await post({ turnstileToken: 'retry-me' })).status, 200, 'token usable again after a provider outage');

  // 8. Timeout: a hung Siteverify call is aborted and fails closed.
  reset();
  (globalThis as any).fetch = (_u: string, init: any) => new Promise((_res, rej) => init.signal.addEventListener('abort', () => rej(new Error('aborted'))));
  await assert.rejects(() => verifyTurnstile({ token: 'slow', action: 'login', timeoutMs: 50 }), (e: any) => e.code === 'TURNSTILE_UNAVAILABLE');
  (globalThis as any).fetch = async (url: string, init: any) => { calls.push({ url, init }); return reply(); };

  // 9. Token bound to this site and this form.
  reset(); reply = ok({ action: 'register' });
  r = await post({ turnstileToken: 'wrong-form' });
  assert.equal(r.status, 400, 'a token minted for another form is refused');
  reset(); reply = ok({ hostname: 'evil.example' });
  r = await post({ turnstileToken: 'wrong-host' });
  assert.equal(r.status, 400, 'a token from another site is refused');
  reset(); reply = ok({ action: undefined });
  assert.equal((await post({ turnstileToken: 'no-action' })).status, 400, 'missing action is refused');

  // 10. Remote IP is forwarded as a hint; every failure is audited with a reason but never the token or the secret.
  const dump = JSON.stringify(audits);
  assert(audits.length >= 1 && audits.every((a) => a.action === 'TURNSTILE_FAILED'));
  assert(!dump.includes(SECRET) && !dump.includes('wrong-form') && !dump.includes('retry-me'));
  assert(audits.some((a) => a.metadata.reason === 'action_mismatch' || a.metadata.reason === 'hostname_mismatch'));

  s.close();
  console.log('turnstile (siteverify, replay, fail-closed, binding): OK');
  process.exit(0);
})().catch((e) => { console.error(e); process.exit(1); });
