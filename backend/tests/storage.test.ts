import assert from 'assert';
import fs from 'fs/promises';
import os from 'os';
import path from 'path';
import { LocalStorageProvider } from '../src/storage/local.storage.provider';
import { StorageError, StorageNotFoundError } from '../src/storage/storage.provider';

(async () => {
  const root = await fs.mkdtemp(path.join(os.tmpdir(), 'szt-'));
  const store = new LocalStorageProvider(path.join(root, 'uploads'));
  await store.healthCheck!();

  const key = 'files/u1/f1/v1/abc-123';
  const data = Buffer.from('hello zero trust');
  assert.deepEqual(await store.uploadFile(key, data, { contentType: 'text/plain' }), { key, size: data.length });
  assert.deepEqual(await store.downloadFile(key), data);
  const meta = await store.getMetadata(key);
  assert(meta && meta.size === data.length && meta.lastModified instanceof Date);

  // overwrite is safe; no temp files left behind
  await store.uploadFile(key, Buffer.from('v2'));
  assert.equal((await store.downloadFile(key)).toString(), 'v2');
  const leftovers = (await fs.readdir(path.join(root, 'uploads/files/u1/f1/v1'))).filter((f) => f.endsWith('.tmp'));
  assert.equal(leftovers.length, 0);

  // missing objects
  assert.equal(await store.getMetadata('files/nope'), null);
  await assert.rejects(() => store.downloadFile('files/nope'), StorageNotFoundError);

  // path traversal and malformed keys are refused
  for (const bad of ['../etc/passwd', 'files/../../x', '/abs/path', 'files//x', 'a/./b', 'files/%2e%2e/x', '', 'files/x y']) {
    await assert.rejects(() => store.uploadFile(bad, data), StorageError, `should reject ${bad}`);
    await assert.rejects(() => store.downloadFile(bad), StorageError, `should reject ${bad}`);
  }
  await assert.rejects(() => fs.stat(path.join(root, 'etc')), 'nothing written outside root');

  // delete is idempotent and prunes empty dirs but keeps the root
  await store.deleteFile(key);
  await store.deleteFile(key);
  assert.equal(await store.getMetadata(key), null);
  await assert.doesNotReject(() => fs.stat(path.join(root, 'uploads')));
  await assert.rejects(() => fs.stat(path.join(root, 'uploads/files')), 'empty parents pruned');

  await fs.rm(root, { recursive: true, force: true });
  console.log('local storage provider: OK');
})().catch((e) => { console.error(e); process.exit(1); });
