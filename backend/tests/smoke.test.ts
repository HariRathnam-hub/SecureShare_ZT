import assert from 'assert';
import http from 'http';
import os from 'os';
import path from 'path';

// No R2_* variables, no Brevo key: the server must still assemble and answer.
// Hermetic: never read a developer's real backend/.env.
process.env.DOTENV_CONFIG_PATH = require('path').join(require('os').tmpdir(), 'szt-no-such.env');
Object.assign(process.env, {
  NODE_ENV: 'development', MONGODB_URI: 'mongodb://localhost:27017/x', CLIENT_URL: 'http://localhost:5173',
  JWT_ACCESS_SECRET: 'a'.repeat(40), JWT_REFRESH_SECRET: 'b'.repeat(40), UPLOAD_DIR: path.join(os.tmpdir(), 'szt-smoke'),
  ALLOWED_ORIGINS: 'https://demo-tunnel.trycloudflare.com, http://127.0.0.1:5173', CLOUDFLARE_ACCESS_ENABLED: 'false',
});
for (const k of ['R2_ACCOUNT_ID', 'R2_ACCESS_KEY_ID', 'R2_SECRET_ACCESS_KEY', 'R2_BUCKET', 'BREVO_API_KEY']) delete process.env[k];

(async () => {
  const { app } = await import('../src/app');
  const { getStorage } = await import('../src/storage');
  await getStorage().healthCheck!(); // what server.ts does at boot

  const server = http.createServer(app).listen(0);
  const port = (server.address() as any).port;
  const get = (p: string, method = 'GET', headers: http.OutgoingHttpHeaders = {}) => new Promise<{ status: number; headers: http.IncomingHttpHeaders; body: string }>((resolve, reject) => {
    http.request({ port, path: p, method, headers }, (res) => { let b = ''; res.on('data', (c) => (b += c)); res.on('end', () => resolve({ status: res.statusCode!, headers: res.headers, body: b })); }).on('error', reject).end();
  });

  assert.equal((await get('/health')).status, 200);
  const h = await get('/health');
  assert(h.headers['strict-transport-security'], 'helmet active');
  // Every Phase 2 route family rejects unauthenticated callers before touching DB or storage.
  for (const [p, m] of [['/api/v1/files', 'GET'], ['/api/v1/files', 'POST'], ['/api/v1/links', 'GET'], ['/api/v1/links/open', 'POST'],
    ['/api/v1/rooms', 'GET'], ['/api/v1/access-requests', 'GET'], ['/api/v1/audit', 'GET'], ['/api/v1/security/overview', 'GET']] as const) {
    assert.equal((await get(p, m)).status, 401, `${m} ${p} must require auth`);
  }
  assert.equal((await get('/api/v1/nope')).status, 404);
  assert.equal((await get('/api/v1/security/overview', 'GET', { authorization: 'Bearer not-a-token' })).status, 401, 'dashboard API rejects bad tokens');

  // CORS: CLIENT_URL plus every ALLOWED_ORIGINS entry is accepted, anything else (including another tunnel host) is not.
  for (const o of ['http://localhost:5173', 'https://demo-tunnel.trycloudflare.com', 'http://127.0.0.1:5173']) {
    assert.equal((await get('/health', 'GET', { origin: o })).headers['access-control-allow-origin'], o, `${o} allowed`);
  }
  const bad = await get('/health', 'GET', { origin: 'https://attacker.trycloudflare.com' });
  assert.equal(bad.status, 403, 'unlisted tunnel origin is rejected');
  assert(!bad.headers['access-control-allow-origin']);

  server.close();
  console.log('boot without R2 + auth gate + CORS allow-list smoke: OK');
  process.exit(0);
})().catch((e) => { console.error(e); process.exit(1); });
