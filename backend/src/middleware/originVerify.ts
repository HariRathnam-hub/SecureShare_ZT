import { createHash, timingSafeEqual } from 'crypto';
import { RequestHandler } from 'express';
import { env } from '../config/env';
import { logger } from '../utils/logger';

export const ORIGIN_VERIFY_HEADER = 'x-origin-verify';
const digest = (v: string) => createHash('sha256').update(v).digest();

/**
 * Optional "origin lock". When ORIGIN_VERIFY_SECRET is set, every request except /health must carry the same value in
 * X-Origin-Verify. A Cloudflare Transform Rule adds it to requests that pass through your zone, so anyone hitting the
 * *.onrender.com hostname directly (bypassing the WAF) is rejected.
 *
 * OFF by default: enabling it before the API is served through a proxied Cloudflare hostname breaks the app, because
 * browsers calling onrender.com directly cannot send the header.
 */
export const originVerify: RequestHandler = (req, res, next) => {
  const secret = env.ORIGIN_VERIFY_SECRET;
  if (!secret || req.path === '/health') return next();
  const given = req.get(ORIGIN_VERIFY_HEADER) ?? '';
  if (!timingSafeEqual(digest(given), digest(secret))) {
    logger.warn('Request rejected: origin verification header missing or invalid', { ip: req.ip, method: req.method, path: req.path });
    return res.status(403).json({ status: 'error', message: 'Forbidden' });
  }
  next();
};
