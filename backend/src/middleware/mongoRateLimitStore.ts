import type { ClientRateLimitInfo, Options, Store } from 'express-rate-limit';
import mongoose from 'mongoose';
import { logger } from '../utils/logger';

export const RATE_LIMIT_COLLECTION = 'ratelimits';

/** The slice of the MongoDB collection API this store needs (kept narrow so tests can inject a fake). */
export interface CounterCollection {
  findOneAndUpdate(filter: Record<string, unknown>, update: Record<string, unknown>, options?: Record<string, unknown>): Promise<unknown>;
  updateOne(filter: Record<string, unknown>, update: Record<string, unknown>): Promise<unknown>;
  deleteOne(filter: Record<string, unknown>): Promise<unknown>;
  createIndex?(spec: Record<string, number>, options?: Record<string, unknown>): Promise<unknown>;
}

const defaultCollection = (): CounterCollection => mongoose.connection.collection(RATE_LIMIT_COLLECTION) as unknown as CounterCollection;

/** Driver v6 returns the document; older drivers return { value }. Accept both. */
const unwrap = (r: any): { hits: number; resetAt: Date } | null => (r && typeof r === 'object' && 'value' in r && !('hits' in r) ? r.value : r) ?? null;

/**
 * TTL index so expired windows are cleaned up. Correctness never depends on it (expiry is checked on every increment),
 * and production runs with autoIndex off, so the server creates it explicitly at boot.
 */
export async function ensureRateLimitIndexes(col: CounterCollection = defaultCollection()): Promise<void> {
  try {
    await col.createIndex?.({ resetAt: 1 }, { expireAfterSeconds: 0, name: 'resetAt_ttl' });
  } catch (err) {
    logger.error('Could not create the rate-limit TTL index (counters still work, but stale rows will not be purged)', { err });
  }
}

/**
 * Fixed-window counters in MongoDB, shared by every API instance and surviving restarts (unlike the default
 * in-memory store). One document per (limiter, key):  { _id: "<limiter>:<key>", hits, resetAt }.
 *
 *   1. $inc the live window (resetAt in the future).
 *   2. No live window: start a new one with an upsert that only matches an EXPIRED or MISSING document. If a concurrent
 *      request already opened a live window, the upsert collides on _id (E11000) and we loop back to step 1, so a burst
 *      at the start of a window can never reset someone else's counter.
 */
export class MongoRateLimitStore implements Store {
  /** Keys incremented here are visible to every instance, so express-rate-limit's double-count check stays enabled. */
  localKeys = false;
  readonly prefix: string;
  private windowMs = 60_000;

  constructor(name: string, private readonly collection: () => CounterCollection = defaultCollection) {
    this.prefix = `${name}:`;
  }

  init(options: Options): void {
    this.windowMs = options.windowMs;
  }

  private id(key: string): string {
    return this.prefix + key;
  }

  async increment(key: string): Promise<ClientRateLimitInfo> {
    const _id = this.id(key);
    const col = this.collection();
    for (let attempt = 0; attempt < 4; attempt += 1) {
      const now = new Date();
      const live = unwrap(await col.findOneAndUpdate({ _id, resetAt: { $gt: now } }, { $inc: { hits: 1 } }, { returnDocument: 'after' }));
      if (live) return { totalHits: live.hits, resetTime: live.resetAt };
      try {
        const fresh = unwrap(
          await col.findOneAndUpdate(
            { _id, resetAt: { $lte: now } },
            { $set: { hits: 1, resetAt: new Date(now.getTime() + this.windowMs) } },
            { upsert: true, returnDocument: 'after' },
          ),
        );
        if (fresh) return { totalHits: fresh.hits, resetTime: fresh.resetAt };
      } catch (err: any) {
        if (err?.code !== 11000) throw err; // a live window appeared concurrently: count into it on the next pass
      }
    }
    throw new Error('Rate-limit store: could not increment counter');
  }

  async decrement(key: string): Promise<void> {
    await this.collection().updateOne({ _id: this.id(key), hits: { $gt: 0 } }, { $inc: { hits: -1 } });
  }

  async resetKey(key: string): Promise<void> {
    await this.collection().deleteOne({ _id: this.id(key) });
  }
}
