import { createLimiter, userKey } from './rateLimiter';

const MIN = 60_000;

// File/link/room routes sit behind `authenticate`, so budgets follow the signed-in account (the IP-based general limit still applies on top).
export const uploadLimiter = createLimiter({ name: 'upload', windowMs: 15 * MIN, limit: 20, key: userKey, message: 'Too many uploads. Try again later.' });
export const downloadLimiter = createLimiter({ name: 'download', windowMs: 15 * MIN, limit: 60, key: userKey, message: 'Too many downloads. Try again later.' });
/** Sharing and access-request creation: user shares, link creation, access requests. */
export const shareLimiter = createLimiter({ name: 'share', windowMs: 15 * MIN, limit: 30, key: userKey, message: 'Too many sharing actions. Try again later.' });
/** Link redemption: brute-force surface for link passwords. Keyed by IP so throwaway accounts do not multiply the budget. */
export const linkLimiter = createLimiter({ name: 'link-redeem', windowMs: 15 * MIN, limit: 30, message: 'Too many link attempts. Try again later.' });
export const lookupLimiter = createLimiter({ name: 'lookup', windowMs: 15 * MIN, limit: 40, key: userKey, message: 'Too many lookups. Try again later.' });
