import assert from 'assert';
import os from 'os';
import path from 'path';

process.env.DOTENV_CONFIG_PATH = path.join(os.tmpdir(), 'szt-no-such.env');
const prod = {
  NODE_ENV: 'production', MONGODB_URI: 'mongodb://localhost:27017/x', CLIENT_URL: 'https://secureshare-zt.pages.dev',
  JWT_ACCESS_SECRET: 'a'.repeat(40), JWT_REFRESH_SECRET: 'b'.repeat(40), BREVO_API_KEY: 'k', EMAIL_FROM_ADDRESS: 'a@example.com',
  TURNSTILE_SECRET_KEY: '0x4AAAAAAAreal-looking-secret',
};
const MANAGED = /^(CLOUDFLARE_|CF_ACCESS_|ALLOWED_ORIGINS|TUNNEL_|TRUST_PROXY|TURNSTILE_|RATE_LIMIT_|CLIENT_IP_|ORIGIN_VERIFY_)/;

function load(extra: Record<string, string>) {
  for (const k of Object.keys(process.env)) if (MANAGED.test(k)) delete process.env[k];
  Object.assign(process.env, prod, extra);
  const id = require.resolve('../src/config/env');
  delete require.cache[id];
  const realExit = process.exit, realError = console.error;
  let status = 0, err = '';
  (process as any).exit = (c: number) => { status = c; throw new Error('exit'); };
  console.error = (...a: unknown[]) => { err += a.map((x) => JSON.stringify(x)).join(' '); };
  try { return { status, err, env: require(id).env as typeof import('../src/config/env').env }; }
  catch { return { status, err, env: undefined }; }
  finally { process.exit = realExit; console.error = realError; }
}

let r = load({});
assert.equal(r.status, 0, r.err);
assert.deepEqual(r.env!.allowedOrigins, ['https://secureshare-zt.pages.dev'], 'production CORS = the Pages origin only');
assert.equal(r.env!.turnstile.enabled, true); assert.equal(r.env!.turnstile.dummy, false);
assert.deepEqual(r.env!.turnstile.expectedHostnames, ['secureshare-zt.pages.dev']);
assert.equal(r.env!.RATE_LIMIT_STORE, 'memory'); assert.equal(r.env!.CLIENT_IP_HEADER, undefined);

// Fail closed: no Turnstile secret, or a Cloudflare dummy secret, refuses to boot in production.
r = load({ TURNSTILE_SECRET_KEY: '' });
assert.equal(r.status, 1); assert.match(r.err, /TURNSTILE_SECRET_KEY/);
for (const dummy of ['1x0000000000000000000000000000000AA', '2x0000000000000000000000000000000AA', '3x0000000000000000000000000000000AA']) {
  r = load({ TURNSTILE_SECRET_KEY: dummy });
  assert.equal(r.status, 1, dummy); assert.match(r.err, /dummy/);
}
// ... but the dummy secret is fine in development (that is what it is for).
r = load({ NODE_ENV: 'development', CLIENT_URL: 'http://localhost:5173', TURNSTILE_SECRET_KEY: '1x0000000000000000000000000000000AA' });
assert.equal(r.status, 0, r.err); assert.equal(r.env!.turnstile.dummy, true);
r = load({ NODE_ENV: 'development', CLIENT_URL: 'http://localhost:5173', TURNSTILE_SECRET_KEY: '' });
assert.equal(r.status, 0); assert.equal(r.env!.turnstile.enabled, false, 'development without a secret skips verification');

// Production CORS must be exact https origins, never localhost.
for (const [k, v] of [['CLIENT_URL', 'http://secureshare-zt.pages.dev'], ['CLIENT_URL', 'https://localhost:5173'], ['CLIENT_URL', 'https://secureshare-zt.pages.dev/app'], ['ALLOWED_ORIGINS', 'http://localhost:5173'], ['ALLOWED_ORIGINS', 'https://127.0.0.1'], ['ALLOWED_ORIGINS', 'http://x.example.com']] as const) {
  r = load({ [k]: v });
  assert.equal(r.status, 1, `${k}=${v}`); assert.match(r.err, new RegExp(k));
}
r = load({ ALLOWED_ORIGINS: 'https://api-admin.example.com' });
assert.equal(r.status, 0, r.err); assert.deepEqual(r.env!.allowedOrigins, ['https://secureshare-zt.pages.dev', 'https://api-admin.example.com']);

// New knobs validate.
r = load({ RATE_LIMIT_STORE: 'redis' }); assert.equal(r.status, 1);
r = load({ RATE_LIMIT_STORE: 'MONGO' }); assert.equal(r.env!.RATE_LIMIT_STORE, 'mongo');
r = load({ CLIENT_IP_HEADER: 'x-forwarded-for' }); assert.equal(r.status, 1, 'only edge-owned headers are accepted');
r = load({ CLIENT_IP_HEADER: 'CF-Connecting-IP' }); assert.equal(r.env!.CLIENT_IP_HEADER, 'cf-connecting-ip');
r = load({ ORIGIN_VERIFY_SECRET: 'short' }); assert.equal(r.status, 1);
r = load({ ORIGIN_VERIFY_SECRET: 'x'.repeat(32) }); assert.equal(r.status, 0, r.err);

console.log('environment validation (production fail-closed, CORS, new settings): OK');
