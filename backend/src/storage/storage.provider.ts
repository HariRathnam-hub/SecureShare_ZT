/**
 * Storage abstraction. Business code (files, versions, delivery) depends ONLY on
 * this interface, so backends are swappable: local disk today; S3-compatible,
 * Cloudflare R2, Azure Blob, etc. later by adding a class and registering it.
 *
 * Contract:
 *  - `key` is an opaque, server-generated path-like string (never user input).
 *  - Providers never expose public URLs. Bytes only leave through the API after
 *    the policy engine and audit log have approved the request.
 */
export interface StoredObject {
  key: string;
  size: number;
}

export interface StorageMetadata {
  key: string;
  size: number;
  lastModified: Date;
}

export interface UploadOptions {
  contentType?: string;
}

export interface StorageProvider {
  readonly name: string;
  uploadFile(key: string, data: Buffer, options?: UploadOptions): Promise<StoredObject>;
  /** Throws StorageNotFoundError when the object does not exist. */
  downloadFile(key: string): Promise<Buffer>;
  /** Idempotent: deleting a missing object is not an error. */
  deleteFile(key: string): Promise<void>;
  /** Resolves null when the object does not exist. */
  getMetadata(key: string): Promise<StorageMetadata | null>;
  /** Optional startup probe (e.g. is the directory writable?). Fail fast, not on first upload. */
  healthCheck?(): Promise<void>;
}

export class StorageError extends Error {
  constructor(message: string, public readonly cause?: unknown) {
    super(message);
    this.name = 'StorageError';
  }
}
export class StorageNotFoundError extends StorageError {
  constructor(key: string) {
    super(`Storage object not found: ${key}`);
    this.name = 'StorageNotFoundError';
  }
}
