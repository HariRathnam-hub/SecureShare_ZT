import assert from 'assert';
import { Types } from 'mongoose';

// Hermetic: never read a developer's real backend/.env.
process.env.DOTENV_CONFIG_PATH = require('path').join(require('os').tmpdir(), 'szt-no-such.env');
Object.assign(process.env, {
  NODE_ENV: 'test', MONGODB_URI: 'mongodb://localhost:27017/x', CLIENT_URL: 'http://localhost:5173',
  JWT_ACCESS_SECRET: 'a'.repeat(40), JWT_REFRESH_SECRET: 'b'.repeat(40),
});

// No database: the models' read methods are replaced with in-memory stubs for this test only.
const thenable = (v: unknown) => ({ lean: async () => v, then: (res: (x: unknown) => unknown, rej?: (e: unknown) => unknown) => Promise.resolve(v).then(res, rej) });
const query = (get: () => unknown) => ({ select: () => thenable(get()), ...thenable(get()) });

(async () => {
  const { User } = await import('../src/modules/user/user.model');
  const { AuditLog } = await import('../src/modules/audit/audit-log.model');
  const { File } = await import('../src/modules/files/file.model');
  const { auditService } = await import('../src/modules/audit/audit.service');
  const { authorizeDownload, APPROVAL_REQUIRED } = await import('../src/modules/files/download-policy.service');
  const { evaluateTrust } = await import('../src/security');
  const { dbRiskEngine } = await import('../src/security/signals');
  const { AppError } = await import('../src/utils/AppError');

  const owner = new Types.ObjectId(), alice = new Types.ObjectId();
  const A = String(alice);
  const UA = 'Mozilla/5.0 test-browser';
  const future = new Date(Date.now() + 86_400_000);
  const session = (ua = UA) => ({ tokenHash: 'x', expiresAt: future, createdAt: new Date(), userAgent: ua });

  // ---- mutable world ----
  const world = {
    user: { isActive: true, refreshTokens: [session()] } as any,
    file: null as any,
    failedLogins: 0, downloads: 0, seenBefore: false, auditFails: false, countThrows: false,
    audits: [] as any[],
  };
  const mkFile = (o: any) => new File({ owner, fileName: 'a.txt', originalName: 'a.txt', mimeType: 'text/plain', size: 1, sha256: 'x', storageKey: 'k', ...o });
  const grant = (extra: any = {}) => ({ user: alice, permission: 'download', grantedBy: owner, ...extra });

  (User as any).findById = () => query(() => world.user);
  (File as any).findById = async () => world.file;
  (AuditLog as any).countDocuments = async (q: any) => {
    if (world.countThrows) throw new Error('db down');
    return q.action === 'LOGIN_FAILED' ? world.failedLogins : world.downloads;
  };
  (AuditLog as any).exists = async () => (world.seenBefore ? { _id: 1 } : null);
  (auditService as any).record = async (_a: unknown, action: string, _t: string, _id: unknown, metadata: any) => {
    if (world.auditFails) throw new Error('audit down');
    world.audits.push({ action, ...metadata });
  };

  const actor = { id: A, email: 'alice@x.com', role: 'user' as const, ip: '1.1.1.1', userAgent: UA };
  const run = (file: any, ctx: any = { purpose: 'project', reason: 'quarterly audit work' }, via: 'direct' | 'link' = 'direct') => {
    world.file = file;
    world.audits.length = 0;
    return authorizeDownload({ actor, file, via, context: ctx });
  };
  const expectDeny = async (p: Promise<unknown>, status: number, code?: string) =>
    assert.rejects(p, (e: unknown) => e instanceof AppError && e.statusCode === status && e.code === code);
  const decisions = () => world.audits.filter((a) => a.action === 'POLICY_DECISION');

  // ---- signals ----
  let r = await dbRiskEngine.assess({ userId: A } as any);
  assert.deepEqual([r.score, r.reasons], [0, []]);
  world.failedLogins = 5; world.downloads = 31;
  r = await dbRiskEngine.assess({ userId: A } as any);
  assert.equal(r.score, 85); // 40 failed logins + 45 volume
  assert(r.reasons.includes('failed_logins:5') && r.reasons.includes('download_volume:31/h'));
  world.failedLogins = 0; world.downloads = 0;
  world.user = { isActive: true, refreshTokens: [] };
  assert(( await dbRiskEngine.assess({ userId: A } as any)).reasons.includes('no_active_session'), 'no live session');
  world.user = { isActive: true, refreshTokens: [session()] };

  // ---- normal download: ALLOW is audited with its reason ----
  const shared = () => mkFile({ classification: 'internal', sharedWith: [grant()] });
  let out = await run(shared());
  assert.equal(out.trust.verdict.decision, 'ALLOW');
  assert.equal(decisions().length, 1);
  assert.equal(decisions()[0].decision, 'ALLOW');
  assert.match(decisions()[0].reason, /score=0 level=low/);

  // ---- recheck: disabled user, revoked share, lapsed grant, closed time window, reclassified to restricted ----
  world.user = { isActive: false, refreshTokens: [session()] };
  await expectDeny(run(shared()), 403);
  assert.equal(decisions()[0].decision, 'DENY');
  assert.equal(decisions()[0].reason, 'user_inactive');
  world.user = { isActive: true, refreshTokens: [session()] };

  await expectDeny(run(mkFile({ classification: 'internal', sharedWith: [] })), 403);
  assert.match(decisions()[0].reason, /^access_revoked/);
  await expectDeny(run(mkFile({ classification: 'internal', sharedWith: [grant({ expiresAt: new Date(Date.now() - 1000) })] })), 403);
  await expectDeny(run(mkFile({ classification: 'internal', sharedWith: [grant()], availableUntil: new Date(Date.now() - 1000) })), 403);
  await expectDeny(run(mkFile({ classification: 'restricted', sharedWith: [grant()] })), 403); // direct share no longer honoured
  world.file = null;
  await expectDeny(authorizeDownload({ actor, file: shared(), via: 'direct', context: {} }), 404); // file deleted meanwhile

  // ---- purpose rule is kept ----
  await expectDeny(run(mkFile({ classification: 'confidential', sharedWith: [grant()] }), {}), 428);

  // ---- adaptive: medium risk (failed logins + unseen user agent) ----
  world.failedLogins = 3;
  world.user = { isActive: true, refreshTokens: [session('other-agent')] }; // current UA has no session and no history => new device
  out = await run(shared());
  assert.equal(out.trust.verdict.decision, 'ALLOW', 'medium risk is allowed for non-sensitive files');
  const conf = () => mkFile({ classification: 'confidential', sharedWith: [grant()] });
  await expectDeny(run(conf()), 403, APPROVAL_REQUIRED);
  assert.equal(decisions()[0].decision, 'REQUIRE_APPROVAL');
  // approved access request on file satisfies the approval requirement
  out = await run(mkFile({ classification: 'confidential', sharedWith: [grant({ requestId: new Types.ObjectId(), expiresAt: future })] }));
  assert.equal(out.trust.verdict.decision, 'ALLOW');
  assert.match(decisions()[0].reason, /approved access request/);

  // ---- adaptive: high risk ----
  world.failedLogins = 6; world.downloads = 20;
  await expectDeny(run(conf()), 403); // DENY, no approval code
  assert.equal(decisions()[0].decision, 'DENY');
  await expectDeny(run(shared()), 403, APPROVAL_REQUIRED);

  // ---- revoked session denies everything ----
  world.failedLogins = 0; world.downloads = 0;
  world.user = { isActive: true, refreshTokens: [] };
  await expectDeny(run(mkFile({ classification: 'public' })), 403);

  // ---- fail closed for restricted when the checks themselves fail ----
  world.user = { isActive: true, refreshTokens: [session()] };
  world.countThrows = true;
  const restricted = mkFile({ classification: 'restricted', sharedWith: [grant({ requestId: new Types.ObjectId(), expiresAt: future })] });
  await expectDeny(run(restricted), 403);
  assert.match(decisions()[0].reason, /fail closed/);
  assert.equal((await evaluateTrust({ userId: A, email: 'a', role: 'user', action: 'download', via: 'direct', resource: { type: 'file', id: 'f', classification: 'internal' } })).verdict.decision, 'ALLOW');
  world.countThrows = false;

  // ---- fail closed when the audit write fails: no decision, no bytes ----
  world.auditFails = true;
  await assert.rejects(run(shared()), /audit down/);
  world.auditFails = false;

  console.log('download re-check + adaptive decisions: OK');
  process.exit(0);
})().catch((e) => { console.error(e); process.exit(1); });
