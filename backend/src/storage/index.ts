import { env } from '../config/env';
import { logger } from '../utils/logger';
import { LocalStorageProvider } from './local.storage.provider';
import type { StorageProvider } from './storage.provider';

export * from './storage.provider';
export { LocalStorageProvider } from './local.storage.provider';

type Factory = () => StorageProvider;

/**
 * Provider registry. Adding a backend later = implement StorageProvider and
 * register it here (or call registerStorageProvider from your own module),
 * then set STORAGE_PROVIDER. No call site changes.
 */
const registry = new Map<string, Factory>([['local', () => new LocalStorageProvider(env.UPLOAD_DIR)]]);

export function registerStorageProvider(name: string, factory: Factory): void {
  registry.set(name, factory);
}

let instance: StorageProvider | undefined;
export function getStorage(): StorageProvider {
  if (!instance) {
    const factory = registry.get(env.STORAGE_PROVIDER);
    if (!factory) throw new Error(`Unknown STORAGE_PROVIDER "${env.STORAGE_PROVIDER}"`);
    instance = factory();
    logger.info(`Storage provider: ${instance.name}`);
  }
  return instance;
}

/** Best-effort bulk delete: attempts every key, never throws, returns the keys that failed. */
export async function deleteMany(provider: StorageProvider, keys: string[]): Promise<string[]> {
  const unique = [...new Set(keys)];
  const results = await Promise.allSettled(unique.map((k) => provider.deleteFile(k)));
  const failed = unique.filter((_, i) => results[i].status === 'rejected');
  if (failed.length) logger.error('Some storage objects could not be deleted', { count: failed.length });
  return failed;
}
