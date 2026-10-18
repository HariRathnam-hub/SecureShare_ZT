import assert from 'assert';
import express from 'express';
import os from 'os';
import path from 'path';
import { Types } from 'mongoose';
import { installFakeDb } from './helpers/fake-db';
import { serve } from './helpers/http';

process.env.DOTENV_CONFIG_PATH = path.join(os.tmpdir(), 'szt-no-such.env');
Object.assign(process.env, {
  NODE_ENV: 'development', MONGODB_URI: 'mongodb://localhost/x', CLIENT_URL: 'http://localhost:5173',
  JWT_ACCESS_SECRET: 'a'.repeat(40), JWT_REFRESH_SECRET: 'b'.repeat(40), UPLOAD_DIR: path.join(os.tmpdir(), 'szt-fs'),
});

const q = (v: unknown) => { const s: any = { select: () => s, lean: () => s, populate: () => s, sort: () => s, then: (a: any, b: any) => Promise.resolve(v).then(a, b) }; return s; };

(async () => {
  const { sanitizeFileName, attachmentDisposition } = await import('../src/utils/filename');
  const { inspectUpload } = await import('../src/modules/files/upload');
  const { sendDelivery } = await import('../src/modules/files/file.controller');
  const { User } = await import('../src/modules/user/user.model');
  const { AuditLog } = await import('../src/modules/audit/audit-log.model');
  const { File } = await import('../src/modules/files/file.model');
  const { FileVersion } = await import('../src/modules/files/file-version.model');
  const { SharedLink } = await import('../src/modules/links/shared-link.model');
  const { signAccessToken } = await import('../src/utils/tokens');
  const { sha256 } = await import('../src/utils/crypto');
  const { app } = await import('../src/app');

  // ================= filenames =================
  const cases: [string, string][] = [
    ['../../etc/passwd', 'passwd'], ['..\\..\\windows\\system32\\cmd.exe', 'cmd.exe'], ['/abs/path/report.pdf', 'report.pdf'],
    ['.htaccess', 'htaccess'], ['..', 'file'], ['   ', 'file'], ['report.pdf.', 'report.pdf'], ['a<b>c:"d|e?f*.txt', 'abcdef.txt'],
    ['invoice\u202Efdp.exe', 'invoicefdp.exe'], ['zero\u200Bwidth.txt', 'zerowidth.txt'], ['nul.txt', '_nul.txt'], ['CON', '_CON'],
    ['line\r\nbreak.txt', 'linebreak.txt'], ['ok name (1).pdf', 'ok name (1).pdf'], ['résumé.pdf', 'résumé.pdf'],
  ];
  for (const [input, want] of cases) assert.equal(sanitizeFileName(input), want, JSON.stringify(input));
  const long = sanitizeFileName('a'.repeat(300) + '.pdf');
  assert(long.length <= 120 && long.endsWith('.pdf'), 'long names keep their extension');
  const cd = attachmentDisposition('evil"; filename=x.exe\r\nSet-Cookie: a=b.txt');
  assert(!/[\r\n]/.test(cd) && !cd.includes('Set-Cookie: '), 'no header injection');
  assert((cd.match(/"/g) || []).length === 2, 'quotes cannot break out of filename=""');
  assert(attachmentDisposition("o'neil (1)*.pdf").includes("filename*=UTF-8''o%27neil%20%281%29.pdf"));
  assert(attachmentDisposition('naïve.pdf').startsWith('attachment; filename="na_ve.pdf"'));

  // ================= upload inspection =================
  const file = (name: string, type: string, buf: Buffer): any => ({ originalname: name, mimetype: type, buffer: buf, size: buf.length });
  const zipDocx = Buffer.concat([Buffer.from('504b0304', 'hex'), Buffer.from('[Content_Types].xml word/document.xml')]);
  const code = (fn: () => unknown) => { try { fn(); return 0; } catch (e: any) { return e.statusCode; } };
  assert.equal(inspectUpload(file('a.pdf', 'application/pdf', Buffer.from('%PDF-1.7 x'))).mimeType, 'application/pdf');
  assert.equal(code(() => inspectUpload(file('a.pdf', 'application/pdf', Buffer.from('MZ\x90\x00 exe')))), 415, 'EXE renamed .pdf');
  assert.equal(code(() => inspectUpload(file('a.png', 'image/png', Buffer.from('<?php system($_GET[0]);')))), 415, 'script as image');
  assert.equal(code(() => inspectUpload(file('a.html', 'text/html', Buffer.from('<script>1</script>')))), 415, 'html not allowed');
  assert.equal(code(() => inspectUpload(file('a.svg', 'image/svg+xml', Buffer.from('<svg onload=1>')))), 415, 'svg not allowed');
  assert.equal(code(() => inspectUpload(file('a.pdf', 'image/png', Buffer.from('%PDF-1')))), 415, 'extension/type mismatch');
  assert.equal(code(() => inspectUpload(file('a.exe', 'application/octet-stream', Buffer.from('MZ')))), 415);
  assert.equal(code(() => inspectUpload(file('a.txt', 'constructor', Buffer.from('x')))), 415, 'prototype-key type is a clean 415, not a 500');
  assert.equal(code(() => inspectUpload(file('a.txt', '__proto__', Buffer.from('x')))), 415);
  assert.equal(code(() => inspectUpload(file('a.txt', 'text/plain', Buffer.from([65, 0, 66])))), 415, 'binary as text');
  assert.equal(code(() => inspectUpload(file('a.docx', 'application/vnd.openxmlformats-officedocument.wordprocessingml.document', zipDocx))), 0);
  assert.equal(code(() => inspectUpload(file('a.docx', 'application/vnd.openxmlformats-officedocument.wordprocessingml.document', Buffer.concat([Buffer.from('504b0304', 'hex'), Buffer.from('payload.exe')])))), 415, 'plain ZIP renamed .docx');
  assert.equal(code(() => inspectUpload(file('a.xlsx', 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet', zipDocx))), 415, 'a docx package is not an xlsx');
  assert.equal(code(() => inspectUpload(undefined)), 400);
  assert.equal(inspectUpload(file(Buffer.from('../../x/evil\u202E.pdf', 'utf8').toString('latin1'), 'application/pdf', Buffer.from('%PDF-1'))).originalName, 'evil.pdf', 'stored name is sanitised');

  // ================= download headers =================
  const hdrApp = express();
  hdrApp.get('/d', (_q, res) => sendDelivery(res, { buffer: Buffer.from('x'), contentType: 'text/html', filename: 'a"\r\nX: y.html', downloadId: 'id1' }));
  hdrApp.get('/ok', (_q, res) => sendDelivery(res, { buffer: Buffer.from('%PDF'), contentType: 'application/pdf', filename: 'r.pdf', downloadId: 'id2' }));
  const hs = serve(hdrApp);
  let r = await hs.call('GET', '/d');
  assert.equal(r.headers['content-type'], 'application/octet-stream', 'non-allow-listed type is never echoed');
  assert(r.headers['content-disposition']!.startsWith('attachment;') && !/[\r\n]/.test(r.headers['content-disposition']!));
  assert.equal(r.headers['x-content-type-options'], 'nosniff'); assert.equal(r.headers['cache-control'], 'no-store');
  assert(String(r.headers['content-security-policy']).includes('sandbox'));
  r = await hs.call('GET', '/ok');
  assert.equal(r.headers['content-type'], 'application/pdf'); assert.equal(r.headers['x-download-id'], 'id2');
  hs.close();

  // ================= authorization / IDOR (routes + real policy code, stubbed persistence) =================
  const db = installFakeDb({ User, AuditLog });
  const owner = db.makeUser({ email: 'owner@x.co', password: 'pw' });
  const stranger = db.makeUser({ email: 'stranger@x.co', password: 'pw' });
  const viewer = db.makeUser({ email: 'viewer@x.co', password: 'pw' });
  const tok = (u: any) => ({ authorization: `Bearer ${signAccessToken(u.id, 'user')}`, 'x-requested-with': 'XMLHttpRequest' });

  const files = new Map<string, any>();
  const mk = (over: any = {}) => {
    const _id = new Types.ObjectId();
    const f: any = {
      _id, id: String(_id), owner: owner._id, fileName: 'f.pdf', originalName: 'f.pdf', mimeType: 'application/pdf', size: 4, sha256: 'x',
      currentVersion: 1, classification: 'internal', sharedWith: [], createdAt: new Date(), updatedAt: new Date(),
      populate: async () => f, ...over,
    };
    files.set(f.id, f); return f;
  };
  let deleted = 0;
  (File as any).findById = (id: string) => q(files.get(String(id)) ?? null);
  (File as any).deleteOne = async () => { deleted++; };
  (File as any).updateOne = async () => { throw new Error('mutation must not happen'); };
  (FileVersion as any).find = () => q([]);

  const future = new Date(Date.now() + 3_600_000), past = new Date(Date.now() - 3_600_000);
  const priv = mk();
  const sharedView = mk({ sharedWith: [{ user: viewer._id, permission: 'view', grantedBy: owner._id }] });
  const sharedExpired = mk({ sharedWith: [{ user: viewer._id, permission: 'download', grantedBy: owner._id, expiresAt: past }] });
  const restricted = mk({ classification: 'restricted', sharedWith: [{ user: viewer._id, permission: 'download', grantedBy: owner._id, expiresAt: future }] }); // direct share, no approved request
  const locked = mk({ sharedWith: [{ user: viewer._id, permission: 'download', grantedBy: owner._id }], availableFrom: future });
  const s = serve(app);
  const call = (m: string, p: string, u?: any, body?: unknown) => s.call(m, p, { headers: u ? tok(u) : {}, body });

  // unauthenticated
  for (const [m, p] of [['GET', `/api/v1/files/${priv.id}`], ['POST', `/api/v1/files/${priv.id}/download`], ['DELETE', `/api/v1/files/${priv.id}`], ['POST', `/api/v1/files/${priv.id}/shares`], ['POST', `/api/v1/files/${priv.id}/links`]] as const)
    assert.equal((await call(m, p)).status, 401, `${m} ${p}`);

  // stranger: existence is not revealed (404, never 403) on every operation
  assert.equal((await call('GET', `/api/v1/files/${priv.id}`, stranger)).status, 404);
  assert.equal((await call('POST', `/api/v1/files/${priv.id}/download`, stranger, {})).status, 404);
  assert.equal((await call('PATCH', `/api/v1/files/${priv.id}`, stranger, { fileName: 'pwn.pdf' })).status, 404);
  assert.equal((await call('DELETE', `/api/v1/files/${priv.id}`, stranger)).status, 404);
  assert.equal((await call('POST', `/api/v1/files/${priv.id}/shares`, stranger, { email: 'stranger@x.co' })).status, 404);
  assert.equal((await call('POST', `/api/v1/files/${priv.id}/links`, stranger, { expiresInMinutes: 5 })).status, 404);
  assert.equal((await call('DELETE', `/api/v1/files/${priv.id}/shares/${viewer.id}`, stranger)).status, 404);
  assert.equal((await call('GET', `/api/v1/files/${priv.id}/audit`, stranger)).status, 404);
  assert.equal(deleted, 0, 'nothing was deleted');
  assert.equal((await call('GET', `/api/v1/files/${new Types.ObjectId()}`, stranger)).status, 404, 'nonexistent id looks identical');
  assert.equal((await call('GET', `/api/v1/files/not-an-id`, stranger)).status, 400, 'malformed ids rejected by validation');
  assert.equal((await call('GET', `/api/v1/files/..%2F..%2Fetc%2Fpasswd`, stranger)).status, 400, 'path-traversal id rejected');
  // a stranger's new-version upload is refused BEFORE the multipart body is read (malformed multipart would otherwise give 400)
  r = await s.call('POST', `/api/v1/files/${priv.id}/versions`, { headers: { ...tok(stranger), 'content-type': 'multipart/form-data' }, body: 'garbage' });
  assert.equal(r.status, 404);
  assert(db.audits.some((a) => a.action === 'ACCESS_DENIED' && a.targetId.toString() === priv.id), 'denials are audited');

  // owner can see their file
  assert.equal((await call('GET', `/api/v1/files/${priv.id}`, owner)).status, 200);

  // grants: view-only may view but not download; expired grant gives nothing; restricted ignores direct shares; time lock applies
  assert.equal((await call('GET', `/api/v1/files/${sharedView.id}`, viewer)).status, 200);
  r = await call('POST', `/api/v1/files/${sharedView.id}/download`, viewer, {});
  assert.equal(r.status, 403); assert.match(r.json.message, /view-only/);
  assert.equal((await call('GET', `/api/v1/files/${sharedExpired.id}`, viewer)).status, 404, 'expired grant');
  assert.equal((await call('POST', `/api/v1/files/${sharedExpired.id}/download`, viewer, {})).status, 404);
  assert.equal((await call('GET', `/api/v1/files/${restricted.id}`, viewer)).status, 404, 'restricted: direct share is not enough');
  r = await call('POST', `/api/v1/files/${locked.id}/download`, viewer, {});
  assert.equal(r.status, 403); assert.match(r.json.message, /not available yet/);
  // revoked: removing the grant removes access immediately (state is re-read on every request)
  sharedView.sharedWith = [];
  assert.equal((await call('GET', `/api/v1/files/${sharedView.id}`, viewer)).status, 404, 'revoked share');
  // viewers/non-owners cannot manage shares or links even with a grant
  assert.equal((await call('POST', `/api/v1/files/${sharedExpired.id}/shares`, viewer, { email: 'stranger@x.co' })).status, 404);
  const g = mk({ sharedWith: [{ user: viewer._id, permission: 'download', grantedBy: owner._id }] });
  r = await call('POST', `/api/v1/files/${g.id}/links`, viewer, { expiresInMinutes: 5 });
  assert.equal(r.status, 403, 'a grantee is not the owner'); assert.match(r.json.message, /owner/);

  // ================= shared links: expired / revoked / exhausted / restricted / wrong password all look the same =================
  const links = new Map<string, any>();
  const mkLink = (fileId: string, over: any = {}) => {
    const token = new Types.ObjectId().toHexString() + new Types.ObjectId().toHexString().slice(0, 16) + 'abcdefabcdef0123';
    const t = token.slice(0, 64).padEnd(64, '0');
    links.set(sha256(t), { _id: new Types.ObjectId(), fileId: new Types.ObjectId(fileId), isActive: true, expiresAt: future, currentDownloads: 0, failedAttempts: 0, maxDownloads: null, ...over });
    return t;
  };
  (SharedLink as any).findOne = (f: any) => q(links.get(f.tokenHash) ?? null);
  const open = (t: string, u = stranger) => call('POST', '/api/v1/links/open', u, { token: t });
  const pubFile = mk({ classification: 'internal' });
  r = await open(mkLink(pubFile.id));
  assert.equal(r.status, 200, 'valid link opens for an authenticated user');
  assert.equal(r.json.data.file.access.canDownload, true); assert(!JSON.stringify(r.json).includes('storageKey'));
  for (const [label, link] of [
    ['expired', mkLink(pubFile.id, { expiresAt: past })], ['revoked', mkLink(pubFile.id, { isActive: false })],
    ['exhausted', mkLink(pubFile.id, { maxDownloads: 1, currentDownloads: 1 })], ['restricted file', mkLink(restricted.id)],
    ['unknown token', 'f'.repeat(64)], ['file deleted', mkLink(new Types.ObjectId().toHexString())],
  ] as const) {
    r = await open(link);
    assert.equal(r.status, 404, label); assert.equal(r.json.message, 'This link is invalid or has expired', `${label}: no oracle`);
  }
  assert.equal((await s.call('POST', '/api/v1/links/open', { body: { token: 'f'.repeat(64) } })).status, 401, 'links need authentication');
  assert.equal((await call('POST', '/api/v1/links/open', stranger, { token: 'short' })).status, 400);

  // private uploads are never web-served
  for (const p of ['/uploads/files/x', '/files/x', '/api/v1/uploads/x', '/static/x']) assert.equal((await s.call('GET', p)).status, 404, p);

  s.close();
  console.log('file security (filenames, signatures, headers, IDOR, grants, links): OK');
  process.exit(0);
})().catch((e) => { console.error(e); process.exit(1); });
