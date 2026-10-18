import assert from 'assert';
import os from 'os';
import path from 'path';

// Hermetic: never read a developer's real backend/.env.
process.env.DOTENV_CONFIG_PATH = path.join(os.tmpdir(), 'szt-no-such.env');

const base = {
  NODE_ENV: 'development', MONGODB_URI: 'mongodb://localhost:27017/x', CLIENT_URL: 'http://localhost:5173',
  JWT_ACCESS_SECRET: 'a'.repeat(40), JWT_REFRESH_SECRET: 'b'.repeat(40),
};
const PHASE3 = /^(CLOUDFLARE_|CF_ACCESS_|ALLOWED_ORIGINS|TUNNEL_|TRUST_PROXY)/;

/** Loads config/env.ts fresh with the given variables; env.ts calls process.exit(1) on invalid configuration. */
function load(extra: Record<string, string>) {
  for (const k of Object.keys(process.env)) if (PHASE3.test(k)) delete process.env[k];
  Object.assign(process.env, base, extra);
  const id = require.resolve('../src/config/env');
  delete require.cache[id];
  const realExit = process.exit, realError = console.error;
  let status = 0, err = '';
  (process as any).exit = (code: number) => { status = code; throw new Error('exit'); };
  console.error = (...a: unknown[]) => { err += a.map((x) => JSON.stringify(x)).join(' '); };
  try {
    return { status, err, env: require(id).env as typeof import('../src/config/env').env };
  } catch {
    return { status, err, env: undefined };
  } finally {
    process.exit = realExit;
    console.error = realError;
  }
}

// Defaults: Access off, nothing extra required.
let r = load({});
assert.equal(r.status, 0, r.err);
assert.deepEqual([r.env!.cloudflareAccess.enabled, r.env!.cloudflareAccess.configured], [false, false]);
assert.deepEqual(r.env!.allowedOrigins, ['http://localhost:5173']);

// Enabled without configuration refuses to boot (no half-configured security).
r = load({ CLOUDFLARE_ACCESS_ENABLED: 'true' });
assert.equal(r.status, 1);
assert.match(r.err, /CF_ACCESS_TEAM_DOMAIN/);
assert.match(r.err, /CF_ACCESS_AUD/);

// Empty lines in .env mean "not set"; disabled + empty is fine.
r = load({ CLOUDFLARE_ACCESS_ENABLED: 'false', CF_ACCESS_TEAM_DOMAIN: '', CF_ACCESS_AUD: '', ALLOWED_ORIGINS: '', TUNNEL_PUBLIC_URL: '' });
assert.equal(r.status, 0, r.err);

// The key-fetch host comes only from config and must be a cloudflareaccess.com host.
r = load({ CLOUDFLARE_ACCESS_ENABLED: 'true', CF_ACCESS_TEAM_DOMAIN: 'evil.example.com', CF_ACCESS_AUD: 'x' });
assert.equal(r.status, 1);

// Short team name and pasted URL forms are normalised.
for (const t of ['acme', 'acme.cloudflareaccess.com', 'https://acme.cloudflareaccess.com/']) {
  r = load({ CLOUDFLARE_ACCESS_ENABLED: 'true', CF_ACCESS_TEAM_DOMAIN: t, CF_ACCESS_AUD: 'aud' });
  assert.equal(r.status, 0, r.err);
  assert.equal(r.env!.cloudflareAccess.teamDomain, 'acme.cloudflareaccess.com');
  assert.equal(r.env!.cloudflareAccess.configured, true);
}

// ALLOWED_ORIGINS: exact origins only.
r = load({ ALLOWED_ORIGINS: 'https://a.trycloudflare.com, https://b.trycloudflare.com/' });
assert.equal(r.status, 1, 'trailing slash rejected');
r = load({ ALLOWED_ORIGINS: 'https://a.trycloudflare.com,http://localhost:5173' });
assert.equal(r.status, 0, r.err);
assert.deepEqual(r.env!.allowedOrigins, ['http://localhost:5173', 'https://a.trycloudflare.com']);

console.log('env validation (tunnel + Access): OK');
