import assert from 'assert';
import { Types } from 'mongoose';
import { PDFDocument } from 'pdf-lib';
import { evaluateFileAccess, evaluateLinkAccess } from '../src/modules/files/access-policy.service';
import { File } from '../src/modules/files/file.model';
import { watermarkPdf } from '../src/services/watermark.service';

const owner = new Types.ObjectId(), alice = new Types.ObjectId(), bob = new Types.ObjectId();
const mk = (o: any) => new File({ owner, fileName: 'a.pdf', originalName: 'a.pdf', mimeType: 'application/pdf', size: 1, sha256: 'x', storageKey: 'k', ...o });
const grant = (user: Types.ObjectId, extra: any = {}) => ({ user, permission: 'download', grantedBy: owner, ...extra });
const hour = 3600e3;

(async () => {
  const now = new Date();
  const A = String(alice), B = String(bob), O = String(owner);

  // owner: always full access, never asked for purpose
  const od = await evaluateFileAccess(mk({ classification: 'restricted' }), O);
  assert(od.canDownload && od.isOwner && !od.requiresPurpose);

  // ---- internal ----
  assert(!(await evaluateFileAccess(mk({ classification: 'internal' }), A)).canView, 'no grant => hidden');
  const g = mk({ classification: 'internal', sharedWith: [grant(alice)] });
  assert((await evaluateFileAccess(g, A)).canDownload);
  assert(!(await evaluateFileAccess(g, B)).canView);
  assert(!(await evaluateFileAccess(g, A)).requiresPurpose);
  assert(!(await evaluateFileAccess(mk({ classification: 'internal', sharedWith: [grant(alice, { expiresAt: new Date(now.getTime() - 1000) })] }), A)).canView, 'expired grant');
  const vo = await evaluateFileAccess(mk({ classification: 'internal', sharedWith: [grant(alice, { permission: 'view' })] }), A);
  assert(vo.canView && !vo.canDownload);

  // ---- public ----
  assert((await evaluateFileAccess(mk({ classification: 'public' }), B)).canDownload);

  // ---- confidential: purpose required ----
  const c = await evaluateFileAccess(mk({ classification: 'confidential', sharedWith: [grant(alice)] }), A);
  assert(c.canDownload && c.requiresPurpose);

  // ---- restricted: only approved-request, time-boxed grants; purpose required ----
  const rid = new Types.ObjectId();
  const future = new Date(now.getTime() + 24 * hour);
  const direct = mk({ classification: 'restricted', sharedWith: [grant(alice)] });
  assert(!(await evaluateFileAccess(direct, A)).canView, 'direct share ignored for restricted');
  const noExpiry = mk({ classification: 'restricted', sharedWith: [grant(alice, { requestId: rid })] });
  assert(!(await evaluateFileAccess(noExpiry, A)).canView, 'restricted grant needs an expiry');
  const approved = mk({ classification: 'restricted', sharedWith: [grant(alice, { requestId: rid, expiresAt: future })] });
  const ra = await evaluateFileAccess(approved, A);
  assert(ra.canDownload && ra.requiresPurpose);
  assert(!(await evaluateFileAccess(approved, B)).canView);
  const lapsed = mk({ classification: 'restricted', sharedWith: [grant(alice, { requestId: rid, expiresAt: new Date(now.getTime() - 1000) })] });
  assert(!(await evaluateFileAccess(lapsed, A)).canView, 'lapsed approval');
  assert(!evaluateLinkAccess(approved, A).canView, 'links never work for restricted');

  // ---- links ----
  assert(evaluateLinkAccess(mk({ classification: 'confidential' }), A).requiresPurpose);
  assert(!evaluateLinkAccess(mk({ classification: 'internal' }), A).requiresPurpose);

  // ---- time lock: availableFrom / availableUntil ----
  const early = mk({ classification: 'public', availableFrom: new Date(now.getTime() + hour), availableUntil: new Date(now.getTime() + 2 * hour) });
  const e = await evaluateFileAccess(early, B);
  assert(e.canView && !e.canDownload && /not available yet/.test(e.denyReason!));
  assert((await evaluateFileAccess(early, O)).canDownload, 'owner exempt');
  assert(!evaluateLinkAccess(early, B).canDownload);
  const expired = mk({ classification: 'public', availableUntil: new Date(now.getTime() - hour) });
  const x = await evaluateFileAccess(expired, B);
  assert(!x.canDownload && /no longer available/.test(x.denyReason!));
  assert((await evaluateFileAccess(mk({ classification: 'public', availableFrom: new Date(now.getTime() - hour), availableUntil: new Date(now.getTime() + hour) }), B)).canDownload, 'inside window');
  assert((await evaluateFileAccess(mk({ classification: 'public', availableFrom: new Date(now.getTime() - hour) }), B)).canDownload, 'open-ended window');
  assert(!(await evaluateFileAccess(mk({ classification: 'internal', sharedWith: [grant(alice)], availableUntil: new Date(now.getTime() - hour) }), A)).canDownload, 'time lock beats grant');

  // ---- watermark ----
  const src = await PDFDocument.create(); src.addPage([300, 400]); src.addPage([600, 300]);
  const out = await watermarkPdf(Buffer.from(await src.save()), { user: 'bob@x.com', userId: '1', timestamp: now.toISOString(), ip: '1.2.3.4', downloadId: 'abcd1234-0000' });
  assert.equal((await PDFDocument.load(out)).getPageCount(), 2);
  await assert.rejects(() => watermarkPdf(Buffer.from('not a pdf'), { user: 'a', userId: '1', timestamp: '', ip: '', downloadId: 'x'.repeat(10) }));

  console.log('policy + watermark: OK');
})().catch((e) => { console.error(e); process.exit(1); });
