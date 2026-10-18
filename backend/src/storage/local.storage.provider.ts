import { randomUUID } from 'crypto';
import fs from 'fs/promises';
import path from 'path';
import {
  StorageError, StorageMetadata, StorageNotFoundError, StorageProvider, StoredObject, UploadOptions,
} from './storage.provider';

// Server-generated keys only look like: files/<id>/<id>/v1/<uuid>
const KEY_PATTERN = /^[A-Za-z0-9][A-Za-z0-9._\-/]*$/;

/** Stores objects as files under a root directory (default: ./uploads). */
export class LocalStorageProvider implements StorageProvider {
  readonly name = 'local';
  private readonly root: string;

  constructor(rootDir: string) {
    this.root = path.resolve(rootDir);
  }

  /** Resolves a key to an absolute path, refusing anything that could escape the root. */
  private resolve(key: string): string {
    if (!KEY_PATTERN.test(key) || key.split('/').some((seg) => seg === '' || seg === '.' || seg === '..')) {
      throw new StorageError('Invalid storage key');
    }
    const full = path.resolve(this.root, key);
    if (!full.startsWith(this.root + path.sep)) throw new StorageError('Invalid storage key');
    return full;
  }

  async healthCheck(): Promise<void> {
    await fs.mkdir(this.root, { recursive: true, mode: 0o700 });
    const probe = path.join(this.root, `.healthcheck-${randomUUID()}`);
    await fs.writeFile(probe, 'ok', { mode: 0o600 });
    await fs.unlink(probe);
  }

  async uploadFile(key: string, data: Buffer, _options?: UploadOptions): Promise<StoredObject> {
    const target = this.resolve(key);
    const tmp = `${target}.${randomUUID()}.tmp`;
    try {
      await fs.mkdir(path.dirname(target), { recursive: true, mode: 0o700 });
      // Write to a temp file, then rename: readers never observe a partial object.
      await fs.writeFile(tmp, data, { flag: 'wx', mode: 0o600 });
      await fs.rename(tmp, target);
    } catch (err) {
      await fs.unlink(tmp).catch(() => undefined);
      throw new StorageError('Failed to store file', err);
    }
    return { key, size: data.length };
  }

  async downloadFile(key: string): Promise<Buffer> {
    try {
      return await fs.readFile(this.resolve(key));
    } catch (err: any) {
      if (err?.code === 'ENOENT') throw new StorageNotFoundError(key);
      if (err instanceof StorageError) throw err;
      throw new StorageError('Failed to read file', err);
    }
  }

  async deleteFile(key: string): Promise<void> {
    const target = this.resolve(key);
    try {
      await fs.unlink(target);
    } catch (err: any) {
      if (err?.code !== 'ENOENT') throw new StorageError('Failed to delete file', err);
    }
    // Best-effort cleanup of now-empty parent directories (never removes the root).
    let dir = path.dirname(target);
    while (dir.startsWith(this.root + path.sep)) {
      try {
        await fs.rmdir(dir);
      } catch {
        break;
      }
      dir = path.dirname(dir);
    }
  }

  async getMetadata(key: string): Promise<StorageMetadata | null> {
    try {
      const st = await fs.stat(this.resolve(key));
      if (!st.isFile()) return null;
      return { key, size: st.size, lastModified: st.mtime };
    } catch (err: any) {
      if (err?.code === 'ENOENT') return null;
      if (err instanceof StorageError) throw err;
      throw new StorageError('Failed to read file metadata', err);
    }
  }
}
