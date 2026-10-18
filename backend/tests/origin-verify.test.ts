import assert from 'assert';
import os from 'os';
import path from 'path';
import { serve } from './helpers/http';

process.env.DOTENV_CONFIG_PATH = path.join(os.tmpdir(), 'szt-no-such.env');
const LOCK = 'l'.repeat(40);
Object.assign(process.env, {
  NODE_ENV: 'development', MONGODB_URI: 'mongodb://localhost/x', CLIENT_URL: 'http://localhost:5173',
  JWT_ACCESS_SECRET: 'a'.repeat(40), JWT_REFRESH_SECRET: 'b'.repeat(40), UPLOAD_DIR: path.join(os.tmpdir(), 'szt-ov'), ORIGIN_VERIFY_SECRET: LOCK,
});

(async () => {
  const { app } = await import('../src/app');
  const s = serve(app);
  assert.equal((await s.call('GET', '/health')).status, 200, '/health stays open for platform probes');
  for (const h of [{}, { 'x-origin-verify': 'wrong' }, { 'x-origin-verify': LOCK + 'x' }, { 'x-origin-verify': '' }]) {
    const r = await s.call('GET', '/api/v1/files', { headers: h });
    assert.equal(r.status, 403, JSON.stringify(h)); assert(!r.body.includes(LOCK));
  }
  assert.equal((await s.call('GET', '/api/v1/files', { headers: { 'x-origin-verify': LOCK } })).status, 401, 'with the header the request reaches normal auth');
  s.close();
  console.log('origin lock (ORIGIN_VERIFY_SECRET): OK');
  process.exit(0);
})().catch((e) => { console.error(e); process.exit(1); });
