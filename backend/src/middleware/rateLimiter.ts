import { Request, RequestHandler } from 'express';
import rateLimit from 'express-rate-limit';
import { env } from '../config/env';
import { SYSTEM_TARGET_ID, auditService } from '../modules/audit/audit.service';
import { sha256 } from '../utils/crypto';
import { ipRateLimitKey } from '../utils/ip';
import { logger } from '../utils/logger';
import { MongoRateLimitStore } from './mongoRateLimitStore';

const MIN = 60_000;
const HOUR = 60 * MIN;

export interface LimiterConfig {
  /** Unique name: prefixes shared-store keys and appears in logs/audit events. */
  name: string;
  windowMs: number;
  limit: number;
  message: string;
  /** Bucket for this request. Defaults to the client IP (IPv6 grouped by /64). */
  key?: (req: Request) => string;
  /** Do not count requests that end below HTTP 400 (so successful logins do not burn the budget). */
  skipSuccessfulRequests?: boolean;
  skip?: (req: Request) => boolean;
  /** Force this limiter onto the per-process memory store even when RATE_LIMIT_STORE=mongo (high-volume, low-risk limits). */
  localOnly?: boolean;
}

/** One log line + one best-effort audit row per client per window: an attacker cannot turn 429s into a write flood. */
function reportExceeded(req: Request, name: string, limit: number): void {
  logger.warn('Rate limit exceeded', { limiter: name, limit, ip: req.ip, userId: req.user?.id, method: req.method, path: `${req.baseUrl}${req.path}` });
  void Promise.resolve(
    auditService.record({ id: req.user?.id, ip: req.ip, userAgent: req.get('user-agent')?.slice(0, 300) }, 'RATE_LIMITED', 'system', SYSTEM_TARGET_ID, {
      limiter: name, limit, method: req.method, path: `${req.baseUrl}${req.path}`,
    }),
  ).catch((err) => logger.error('Rate-limit audit write failed', { err }));
}

export function createLimiter(cfg: LimiterConfig): RequestHandler {
  const useMongo = env.RATE_LIMIT_STORE === 'mongo' && !cfg.localOnly;
  return rateLimit({
    windowMs: cfg.windowMs,
    limit: cfg.limit,
    standardHeaders: true,
    legacyHeaders: false,
    keyGenerator: (req) => (cfg.key ?? ((r: Request) => ipRateLimitKey(r.ip)))(req as Request),
    skipSuccessfulRequests: cfg.skipSuccessfulRequests ?? false,
    skip: cfg.skip ? (req) => cfg.skip!(req as Request) : undefined,
    // A store outage must not take the API down; it is logged by express-rate-limit. (Mongo being down breaks auth anyway.)
    passOnStoreError: true,
    ...(useMongo ? { store: new MongoRateLimitStore(cfg.name) } : {}),
    handler: (req, res) => {
      const info = (req as Request & { rateLimit?: { limit: number; used: number; resetTime?: Date } }).rateLimit;
      const resetAt = info?.resetTime?.getTime() ?? Date.now() + cfg.windowMs;
      const retryAfter = Math.max(1, Math.ceil((resetAt - Date.now()) / 1000));
      res.setHeader('Retry-After', String(retryAfter));
      if (info && info.used === info.limit + 1) reportExceeded(req as Request, cfg.name, info.limit);
      res.status(429).json({ status: 'error', message: cfg.message, code: 'RATE_LIMITED', retryAfterSeconds: retryAfter });
    },
  });
}

// ---- key helpers ----------------------------------------------------------------------------------------------------
const normEmail = (req: Request): string => (typeof req.body?.email === 'string' ? req.body.email.trim().toLowerCase().slice(0, 254) : '');
/** Per-account bucket. Hashed so addresses never sit in the limiter store. */
export const emailKey = (req: Request): string => {
  const e = normEmail(req);
  return e ? `email:${sha256(e).slice(0, 32)}` : ipRateLimitKey(req.ip);
};
/** Account + client IP: one attacker cannot lock a victim out of their own account from another address. */
export const emailAndIpKey = (req: Request): string => {
  const e = normEmail(req);
  return e ? `acct:${sha256(e).slice(0, 32)}:${ipRateLimitKey(req.ip)}` : ipRateLimitKey(req.ip);
};
/** Authenticated routes: budget follows the account. Falls back to IP if a limiter is ever mounted before authenticate. */
export const userKey = (req: Request): string => (req.user ? `user:${req.user.id}` : ipRateLimitKey(req.ip));

// ---- general API limit ----------------------------------------------------------------------------------------------
/** Baseline for all API traffic (per process; /health is exempt so platform probes are never throttled). */
export const globalLimiter = createLimiter({
  name: 'global', windowMs: 15 * MIN, limit: 300, message: 'Too many requests. Try again later.',
  skip: (req) => req.path === '/health', localOnly: true,
});

// ---- authentication -------------------------------------------------------------------------------------------------
export const loginLimiter = createLimiter({ name: 'login-ip', windowMs: 15 * MIN, limit: 20, message: 'Too many sign-in attempts. Try again in a few minutes.' });
export const loginAccountLimiter = createLimiter({
  name: 'login-account', windowMs: 15 * MIN, limit: 8, key: emailAndIpKey, skipSuccessfulRequests: true,
  message: 'Too many sign-in attempts for this account. Try again in a few minutes.',
});
export const registerLimiter = createLimiter({ name: 'register', windowMs: HOUR, limit: 10, message: 'Too many sign-up attempts. Try again later.' });
export const verifyEmailLimiter = createLimiter({ name: 'verify-email', windowMs: HOUR, limit: 20, message: 'Too many attempts. Try again later.' });
export const resendVerificationLimiter = createLimiter({ name: 'resend-verification-ip', windowMs: HOUR, limit: 6, message: 'Too many requests. Try again later.' });
export const resendVerificationEmailLimiter = createLimiter({ name: 'resend-verification-email', windowMs: HOUR, limit: 3, key: emailKey, message: 'Too many requests. Try again later.' });

// ---- password reset (email-sending, so also limited per target address to stop mail-bombing) -----------------------------
export const passwordResetLimiter = createLimiter({ name: 'password-reset-ip', windowMs: HOUR, limit: 6, message: 'Too many password reset requests. Try again later.' });
export const passwordResetEmailLimiter = createLimiter({ name: 'password-reset-email', windowMs: HOUR, limit: 3, key: emailKey, message: 'Too many password reset requests for this account. Try again later.' });
export const resetPasswordLimiter = createLimiter({ name: 'reset-password', windowMs: HOUR, limit: 10, message: 'Too many attempts. Try again later.' });

/** Refresh is called on every page load, so it gets more headroom. */
export const refreshLimiter = createLimiter({ name: 'refresh', windowMs: 15 * MIN, limit: 60, message: 'Too many requests. Try again later.', localOnly: true });
