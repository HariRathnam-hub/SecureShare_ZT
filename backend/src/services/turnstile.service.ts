import { createHash } from 'crypto';
import net from 'net';
import { env } from '../config/env';
import { logger } from '../utils/logger';

export const TURNSTILE_ACTIONS = ['login', 'register', 'forgot-password', 'reset-password'] as const;
export type TurnstileAction = (typeof TURNSTILE_ACTIONS)[number];

export const SITEVERIFY_URL = 'https://challenges.cloudflare.com/turnstile/v0/siteverify';
const TIMEOUT_MS = 5_000;
const TOKEN_MAX_LENGTH = 2_048; // Cloudflare's documented maximum
const TOKEN_TTL_MS = 5 * 60_000; // tokens are valid for 300 s
const REPLAY_CACHE_MAX = 10_000;

export type TurnstileCode = 'TURNSTILE_REQUIRED' | 'TURNSTILE_FAILED' | 'TURNSTILE_EXPIRED' | 'TURNSTILE_UNAVAILABLE';

/** A rejected verification. `reason` is for logs/audit only and is never sent to the client. */
export class TurnstileRejection extends Error {
  constructor(
    public readonly status: number,
    public readonly code: TurnstileCode,
    public readonly publicMessage: string,
    public readonly reason: string,
  ) {
    super(reason);
    this.name = 'TurnstileRejection';
  }
}

const rejections = {
  required: (reason: string) => new TurnstileRejection(400, 'TURNSTILE_REQUIRED', 'Complete the security check and try again.', reason),
  failed: (reason: string) => new TurnstileRejection(400, 'TURNSTILE_FAILED', 'Security check failed. Please try again.', reason),
  expired: (reason: string) => new TurnstileRejection(400, 'TURNSTILE_EXPIRED', 'The security check expired or was already used. Please try again.', reason),
  unavailable: (reason: string) => new TurnstileRejection(503, 'TURNSTILE_UNAVAILABLE', 'The security check is temporarily unavailable. Please try again shortly.', reason),
};

/**
 * Local replay guard (defence in depth). Cloudflare already refuses a second redemption of a token
 * ("timeout-or-duplicate"); this additionally stops concurrent duplicate submissions from reaching Cloudflare at all.
 * Per-process only: with several API instances Cloudflare remains the authority.
 */
const claimed = new Map<string, number>();
const digest = (t: string) => createHash('sha256').update(t).digest('hex');
function claim(d: string): boolean {
  const now = Date.now();
  for (const [k, exp] of claimed) {
    if (exp > now) break; // Map keeps insertion order, so the oldest entries come first
    claimed.delete(k);
  }
  if ((claimed.get(d) ?? 0) > now) return false;
  if (claimed.size >= REPLAY_CACHE_MAX) claimed.delete(claimed.keys().next().value as string);
  claimed.set(d, now + TOKEN_TTL_MS);
  return true;
}
/** Test helper. */
export const resetTurnstileState = () => claimed.clear();

let warnedSkip = false;

interface SiteverifyResponse {
  success?: boolean;
  'error-codes'?: unknown;
  hostname?: unknown;
  action?: unknown;
}

/**
 * Verifies a Turnstile token with Cloudflare Siteverify. Resolves when the token is valid for this form on this site;
 * otherwise throws TurnstileRejection. Fails CLOSED: network errors, timeouts, non-200 answers, malformed answers and a
 * rejected secret all reject the request (503) instead of letting it through.
 */
export async function verifyTurnstile(p: { token: unknown; action: TurnstileAction; ip?: string; timeoutMs?: number }): Promise<{ skipped: boolean }> {
  if (!env.turnstile.enabled) {
    // Boot refuses to start in production without a secret, so this branch is development convenience only.
    if (env.isProd) throw rejections.unavailable('secret_not_configured');
    if (!warnedSkip) {
      warnedSkip = true;
      logger.warn('Turnstile verification is SKIPPED because TURNSTILE_SECRET_KEY is not set (development only)');
    }
    return { skipped: true };
  }

  if (typeof p.token !== 'string' || p.token.length === 0) throw rejections.required('missing_token');
  if (p.token.length > TOKEN_MAX_LENGTH) throw rejections.failed('token_too_long');

  const d = digest(p.token);
  // Cloudflare's dummy secret accepts one fixed token forever, so replay tracking would break local development with it.
  const track = !env.turnstile.dummy;
  if (track && !claim(d)) throw rejections.expired('replayed_locally');

  const body = new URLSearchParams({ secret: env.turnstile.secret as string, response: p.token });
  if (p.ip && net.isIP(p.ip)) body.set('remoteip', p.ip);

  const abort = new AbortController();
  const timer = setTimeout(() => abort.abort(), p.timeoutMs ?? TIMEOUT_MS);
  let data: SiteverifyResponse;
  try {
    const res = await fetch(SITEVERIFY_URL, { method: 'POST', body, signal: abort.signal });
    if (!res.ok) throw new Error(`siteverify HTTP ${res.status}`);
    data = (await res.json()) as SiteverifyResponse;
    if (!data || typeof data !== 'object') throw new Error('siteverify returned a non-object');
  } catch (err) {
    // The token may not have been consumed: let the user retry with it.
    if (track) claimed.delete(d);
    logger.error('Turnstile Siteverify call failed (failing closed)', { error: err instanceof Error ? err.message : String(err) });
    throw rejections.unavailable('provider_error');
  } finally {
    clearTimeout(timer);
  }

  if (data.success !== true) {
    const codes = Array.isArray(data['error-codes']) ? data['error-codes'].filter((c): c is string => typeof c === 'string') : [];
    if (codes.includes('missing-input-secret') || codes.includes('invalid-input-secret')) {
      logger.error('Cloudflare rejected TURNSTILE_SECRET_KEY: check the secret in the environment (failing closed)');
      throw rejections.unavailable(codes.join(','));
    }
    if (codes.includes('internal-error')) {
      if (track) claimed.delete(d);
      throw rejections.unavailable('internal-error');
    }
    if (codes.includes('timeout-or-duplicate')) throw rejections.expired('timeout-or-duplicate');
    throw rejections.failed(codes.join(',') || 'unsuccessful');
  }

  // Bind the token to this site and this form so a token minted elsewhere (or for another form) cannot be replayed here.
  if (!env.turnstile.dummy) {
    const host = typeof data.hostname === 'string' ? data.hostname.toLowerCase() : '';
    if (!env.turnstile.expectedHostnames.includes(host)) throw rejections.failed('hostname_mismatch');
    if (data.action !== p.action) throw rejections.failed('action_mismatch');
  }
  return { skipped: false };
}
