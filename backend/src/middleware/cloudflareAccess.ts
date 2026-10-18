import { RequestHandler } from 'express';
import { env } from '../config/env';
import { EdgeVerificationError } from '../security/cloudflare-access';
import { security } from '../security';
import type { EdgeIdentityVerifier } from '../security/types';
import { logger } from '../utils/logger';

/** In-memory counters since process start. Shown on the security dashboard; they are not an audit record. */
export const accessStats = {
  verified: 0,
  rejected: 0,
  lastRejectedAt: null as Date | null,
  lastRejectReason: null as string | null,
};

const reject = (res: Parameters<RequestHandler>[1], status: number, code: string, message: string) => {
  accessStats.rejected += 1;
  accessStats.lastRejectedAt = new Date();
  accessStats.lastRejectReason = code;
  res.status(status).json({ status: 'error', message });
};

/**
 * Requires a verified Cloudflare Access assertion on every request that reaches it.
 * The verifier is injectable so the behaviour can be tested without Cloudflare.
 */
export const requireCloudflareAccess = (verifier: EdgeIdentityVerifier): RequestHandler => async (req, res, next) => {
  try {
    const edge = await verifier.verify(req.headers);
    if (!edge) return reject(res, 401, 'missing_assertion', 'Cloudflare Access verification required');
    req.trust = { ...req.trust, edge };
    accessStats.verified += 1;
    next();
  } catch (err) {
    if (err instanceof EdgeVerificationError) {
      logger.warn('Cloudflare Access assertion rejected', { code: err.code, ip: req.ip });
      return reject(res, err.status, err.code, err.status === 503 ? 'Unable to verify identity right now' : 'Cloudflare Access verification failed');
    }
    next(err);
  }
};

/** Mounted once in app.ts. A pass-through unless CLOUDFLARE_ACCESS_ENABLED=true, so local development is unchanged. */
export const cloudflareAccessGate: RequestHandler = env.cloudflareAccess.enabled
  ? requireCloudflareAccess(security.edge)
  : (_req, _res, next) => next();
