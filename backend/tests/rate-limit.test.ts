import assert from 'assert';
import express from 'express';
import os from 'os';
import path from 'path';
import { serve } from './helpers/http';

process.env.DOTENV_CONFIG_PATH = path.join(os.tmpdir(), 'szt-no-such.env');
Object.assign(process.env, {
  NODE_ENV: 'development', MONGODB_URI: 'mongodb://localhost/x', CLIENT_URL: 'http://localhost:5173',
  JWT_ACCESS_SECRET: 'a'.repeat(40), JWT_REFRESH_SECRET: 'b'.repeat(40), UPLOAD_DIR: path.join(os.tmpdir(), 'szt-rl'),
  CLIENT_IP_HEADER: 'cf-connecting-ip', TRUST_PROXY_HOPS: '1',
});

(async () => {
  const { ipRateLimitKey, parseSingleIp } = await import('../src/utils/ip');
  const { AuditLog } = await import('../src/modules/audit/audit-log.model');
  const audits: any[] = [];
  (AuditLog as any).create = async (d: any) => { audits.push(d); return d; };
  const { createLimiter, emailKey, emailAndIpKey } = await import('../src/middleware/rateLimiter');
  const { clientIp } = await import('../src/middleware/clientIp');
  const { MongoRateLimitStore } = await import('../src/middleware/mongoRateLimitStore');

  // ---- IP keys: IPv6 is bucketed by /64, mapped IPv4 collapses to IPv4 ----
  assert.equal(ipRateLimitKey('203.0.113.9'), 'ip:203.0.113.9');
  assert.equal(ipRateLimitKey('::ffff:203.0.113.9'), 'ip:203.0.113.9');
  assert.equal(ipRateLimitKey('2001:db8:1:2:aaaa:bbbb:cccc:dddd'), ipRateLimitKey('2001:db8:1:2::1'), 'same /64 -> same bucket');
  assert.notEqual(ipRateLimitKey('2001:db8:1:2::1'), ipRateLimitKey('2001:db8:1:3::1'), 'different /64 -> different bucket');
  assert.equal(ipRateLimitKey(undefined), 'ip:unknown');
  assert.equal(parseSingleIp('1.2.3.4'), '1.2.3.4');
  for (const bad of ['1.2.3.4, 5.6.7.8', '1.2.3.4:80', 'evil', '', undefined]) assert.equal(parseSingleIp(bad as any), undefined, String(bad));

  // ---- limiter behaviour through a real HTTP stack ----
  const app = express();
  app.set('trust proxy', 1);
  app.use(clientIp);
  app.use(express.json());
  app.post('/strict', createLimiter({ name: 't-strict', windowMs: 60_000, limit: 3, message: 'Slow down.' }), (_q, r) => r.json({ ok: true }));
  app.post('/acct', createLimiter({ name: 't-acct', windowMs: 60_000, limit: 2, key: emailAndIpKey, message: 'acct' }), (_q, r) => r.json({ ok: true }));
  app.post('/mail', createLimiter({ name: 't-mail', windowMs: 60_000, limit: 1, key: emailKey, message: 'mail' }), (_q, r) => r.json({ ok: true }));
  app.get('/whoami', (req, res) => res.json({ ip: req.ip }));
  const s = serve(app);
  const as = (ip: string) => ({ 'cf-connecting-ip': ip });

  for (let i = 0; i < 3; i++) assert.equal((await s.call('POST', '/strict', { headers: as('198.51.100.1') })).status, 200);
  const blocked = await s.call('POST', '/strict', { headers: as('198.51.100.1') });
  assert.equal(blocked.status, 429);
  assert(Number(blocked.headers['retry-after']) >= 1 && Number(blocked.headers['retry-after']) <= 60, 'Retry-After header present');
  assert.equal(blocked.json.code, 'RATE_LIMITED'); assert.equal(blocked.json.message, 'Slow down.');
  assert.equal(blocked.json.retryAfterSeconds, Number(blocked.headers['retry-after']));
  assert.equal((await s.call('POST', '/strict', { headers: as('198.51.100.2') })).status, 200, 'another client is unaffected');
  await s.call('POST', '/strict', { headers: as('198.51.100.1') }); await s.call('POST', '/strict', { headers: as('198.51.100.1') });
  await new Promise((r) => setTimeout(r, 50));
  assert.equal(audits.filter((a) => a.action === 'RATE_LIMITED').length, 1, 'one audit row per client per window, not one per rejected request');
  assert.equal(audits[0].metadata.limiter, 't-strict');

  // per account+IP: attacker on another IP cannot exhaust the victim's budget; email hashed in keys
  const body = { email: 'Victim@Example.com' };
  for (let i = 0; i < 2; i++) await s.call('POST', '/acct', { headers: as('192.0.2.50'), body });
  assert.equal((await s.call('POST', '/acct', { headers: as('192.0.2.50'), body })).status, 429);
  assert.equal((await s.call('POST', '/acct', { headers: as('192.0.2.51'), body })).status, 200, 'different IP, same account: separate bucket');
  assert.equal((await s.call('POST', '/acct', { headers: as('192.0.2.50'), body: { email: ' victim@example.com ' } })).status, 429, 'email normalised');
  // per target address regardless of IP (mail-bombing guard)
  assert.equal((await s.call('POST', '/mail', { headers: as('192.0.2.60'), body })).status, 200);
  assert.equal((await s.call('POST', '/mail', { headers: as('192.0.2.61'), body })).status, 429);
  assert(!emailKey({ body } as any).includes('victim'), 'no plaintext address in limiter keys');
  assert(!emailAndIpKey({ body, ip: '1.1.1.1' } as any).includes('victim'));

  // ---- client IP resolution ----
  assert.equal((await s.call('GET', '/whoami', { headers: { 'cf-connecting-ip': '203.0.113.7', 'x-forwarded-for': '9.9.9.9, 8.8.8.8' } })).json.ip, '203.0.113.7', 'trusted header wins over spoofable XFF');
  assert.equal((await s.call('GET', '/whoami', { headers: { 'cf-connecting-ip': '1.1.1.1, 2.2.2.2', 'x-forwarded-for': '9.9.9.9' } })).json.ip, '9.9.9.9', 'list in header -> ignored, falls back to trust-proxy value');
  assert.equal((await s.call('GET', '/whoami', { headers: { 'cf-connecting-ip': 'not-an-ip' } })).json.ip.includes('not'), false, 'garbage ignored');
  s.close();

  // ---- Mongo-backed shared store (fake collection implementing the operator semantics used) ----
  const rows = new Map<string, { _id: string; hits: number; resetAt: Date }>();
  let dupOnce = false;
  const col: any = {
    async findOneAndUpdate(f: any, u: any, o: any = {}) {
      const row = rows.get(f._id);
      const matches = row && (!f.resetAt || ('$gt' in f.resetAt ? row.resetAt > f.resetAt.$gt : row.resetAt <= f.resetAt.$lte));
      if (matches) { if (u.$inc) row!.hits += u.$inc.hits; if (u.$set) Object.assign(row!, u.$set); return { ...row }; }
      if (o.upsert) {
        if (row || dupOnce) { // a live row exists (or a concurrent insert won): Mongo raises E11000
          if (dupOnce && !row) { dupOnce = false; rows.set(f._id, { _id: f._id, hits: 5, resetAt: new Date(Date.now() + 1000) }); }
          throw Object.assign(new Error('E11000'), { code: 11000 });
        }
        const n = { _id: f._id, ...u.$set }; rows.set(f._id, n); return { ...n };
      }
      return null;
    },
    async updateOne(f: any, u: any) { const r = rows.get(f._id); if (r && r.hits > 0) r.hits += u.$inc.hits; },
    async deleteOne(f: any) { rows.delete(f._id); },
  };
  const store = new MongoRateLimitStore('unit', () => col);
  store.init({ windowMs: 1000 } as any);
  assert.equal((await store.increment('k')).totalHits, 1);
  assert.equal((await store.increment('k')).totalHits, 2);
  assert.equal((await store.increment('other')).totalHits, 1, 'keys are independent');
  await store.decrement('k');
  assert.equal((await store.increment('k')).totalHits, 2);
  const t0 = rows.get('unit:k')!.resetAt.getTime();
  rows.get('unit:k')!.resetAt = new Date(Date.now() - 1);   // window expires
  const fresh = await store.increment('k');
  assert.equal(fresh.totalHits, 1, 'expired window restarts at 1'); assert(fresh.resetTime!.getTime() > t0 - 1);
  dupOnce = true;                                              // concurrent window creation: E11000 -> retries into the live window
  assert.equal((await store.increment('race')).totalHits, 6);
  await store.resetKey('k');
  assert.equal(rows.has('unit:k'), false);
  assert.equal(store.localKeys, false);

  console.log('rate limits (429 + Retry-After, per-account, IPv6, client IP, shared store): OK');
  process.exit(0);
})().catch((e) => { console.error(e); process.exit(1); });
