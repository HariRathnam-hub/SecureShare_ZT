import assert from 'assert';
import { generateKeyPairSync, KeyObject } from 'crypto';
import express from 'express';
import http from 'http';
import jwt from 'jsonwebtoken';
import { CloudflareAccessVerifier, EdgeVerificationError } from '../src/security/cloudflare-access';

// The middleware imports ../security (and therefore env). Provide a valid environment first.
// Hermetic: never read a developer's real backend/.env.
process.env.DOTENV_CONFIG_PATH = require('path').join(require('os').tmpdir(), 'szt-no-such.env');
Object.assign(process.env, {
  NODE_ENV: 'test', MONGODB_URI: 'mongodb://localhost:27017/x', CLIENT_URL: 'http://localhost:5173',
  JWT_ACCESS_SECRET: 'a'.repeat(40), JWT_REFRESH_SECRET: 'b'.repeat(40),
});

const TEAM = 'acme.cloudflareaccess.com';
const AUD = 'aud-tag-123';
const ISS = `https://${TEAM}`;

const pair = () => generateKeyPairSync('rsa', { modulusLength: 2048 });
const good = pair();
const other = pair();
const jwkOf = (pub: KeyObject, kid: string) => ({ ...pub.export({ format: 'jwk' }), kid, alg: 'RS256', use: 'sig' });
const sign = (key: KeyObject, kid: string, claims: object = {}, opts: jwt.SignOptions = {}) =>
  jwt.sign({ email: 'Alice@Example.com', ...claims }, key, { algorithm: 'RS256', keyid: kid, issuer: ISS, audience: [AUD], subject: 'user-1', expiresIn: '5m', ...opts });

let fetches = 0;
let published = [jwkOf(good.publicKey, 'k1')];
const fetchStub = (async (url: string) => {
  fetches += 1;
  assert.equal(url, `${ISS}/cdn-cgi/access/certs`, 'keys come only from the configured team domain');
  return { ok: true, status: 200, json: async () => ({ keys: published }) };
}) as unknown as typeof fetch;

const rejects = async (p: Promise<unknown>, code: string) =>
  assert.rejects(p, (e: unknown) => e instanceof EdgeVerificationError && e.code === code, `expected ${code}`);

(async () => {
  const v = new CloudflareAccessVerifier({ teamDomain: TEAM, audience: AUD, fetchImpl: fetchStub, refreshCooldownMs: 0 });

  // ---- valid assertion ----
  const id = await v.verifyToken(sign(good.privateKey, 'k1'));
  assert.equal(id.provider, 'cloudflare-access');
  assert.equal(id.email, 'alice@example.com');
  assert.equal(id.subject, 'user-1');
  await v.verifyToken(sign(good.privateKey, 'k1'));
  assert.equal(fetches, 1, 'keys are cached between requests');

  // ---- every required check ----
  await rejects(v.verifyToken(sign(good.privateKey, 'k1', {}, { expiresIn: -10 })), 'invalid_token'); // expired
  await rejects(v.verifyToken(sign(good.privateKey, 'k1', {}, { audience: ['someone-else'] })), 'invalid_token'); // audience
  await rejects(v.verifyToken(sign(good.privateKey, 'k1', {}, { issuer: 'https://evil.cloudflareaccess.com' })), 'invalid_token'); // issuer
  await rejects(v.verifyToken(sign(other.privateKey, 'k1')), 'invalid_token'); // signature from a different key
  const noExp = jwt.sign({ email: 'a@b.c' }, good.privateKey, { algorithm: 'RS256', keyid: 'k1', issuer: ISS, audience: AUD });
  await rejects(v.verifyToken(noExp), 'invalid_token'); // no expiry claim
  await rejects(v.verifyToken(jwt.sign({ email: 'a@b.c' }, 'secret', { algorithm: 'HS256', keyid: 'k1', issuer: ISS, audience: AUD, expiresIn: '5m' })), 'invalid_token'); // alg confusion
  await rejects(v.verifyToken('not.a.jwt'), 'malformed');
  await rejects(v.verifyToken(sign(good.privateKey, 'unknown-kid')), 'unknown_key');

  // ---- key rotation: unknown kid triggers a refresh ----
  const rotated = pair();
  published = [jwkOf(good.publicKey, 'k1'), jwkOf(rotated.publicKey, 'k2')];
  assert.equal((await v.verifyToken(sign(rotated.privateKey, 'k2'))).email, 'alice@example.com');

  // ---- header handling: only the signed assertion counts ----
  assert.equal(await v.verify({}), null, 'no assertion => null');
  assert.equal(await v.verify({ 'cf-access-authenticated-user-email': 'alice@example.com' }), null, 'email header alone is never trusted');
  assert.equal((await v.verify({ 'cf-access-jwt-assertion': sign(good.privateKey, 'k1') }))?.email, 'alice@example.com');

  // ---- keys unavailable => fail closed (503) ----
  const down = new CloudflareAccessVerifier({ teamDomain: TEAM, audience: AUD, fetchImpl: (async () => { throw new Error('offline'); }) as unknown as typeof fetch });
  await assert.rejects(down.verifyToken(sign(good.privateKey, 'k1')), (e: unknown) => e instanceof EdgeVerificationError && e.status === 503);

  // ---- middleware over real HTTP ----
  const { requireCloudflareAccess, accessStats } = await import('../src/middleware/cloudflareAccess');
  const app = express();
  app.use(requireCloudflareAccess(v));
  app.get('/whoami', (req, res) => res.json({ edge: req.trust?.edge?.email }));
  const server = http.createServer(app).listen(0);
  const port = (server.address() as any).port;
  const get = (headers: http.OutgoingHttpHeaders) => new Promise<{ status: number; body: any }>((resolve, reject) => {
    http.get({ port, path: '/whoami', headers }, (res) => { let b = ''; res.on('data', (c) => (b += c)); res.on('end', () => resolve({ status: res.statusCode!, body: JSON.parse(b) })); }).on('error', reject);
  });
  assert.equal((await get({})).status, 401);
  assert.equal((await get({ 'Cf-Access-Authenticated-User-Email': 'alice@example.com' })).status, 401, 'forged email header rejected');
  assert.equal((await get({ 'Cf-Access-Jwt-Assertion': sign(other.privateKey, 'k1') })).status, 401, 'forged JWT rejected');
  const ok = await get({ 'Cf-Access-Jwt-Assertion': sign(good.privateKey, 'k1') });
  assert.equal(ok.status, 200);
  assert.equal(ok.body.edge, 'alice@example.com');
  assert.equal(accessStats.verified, 1);
  assert.equal(accessStats.rejected, 3);
  server.close();

  console.log('cloudflare access verification: OK');
  process.exit(0);
})().catch((e) => { console.error(e); process.exit(1); });
