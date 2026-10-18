import { createPublicKey, KeyObject } from 'crypto';
import jwt from 'jsonwebtoken';
import type { EdgeIdentity, EdgeIdentityVerifier } from './types';

export const ACCESS_JWT_HEADER = 'cf-access-jwt-assertion'; // Node lower-cases incoming header names

/** `status` is the HTTP status the middleware answers with; `code` is a stable reason for logs/stats. */
export class EdgeVerificationError extends Error {
  constructor(
    public readonly code: 'missing_assertion' | 'malformed' | 'unknown_key' | 'invalid_token' | 'keys_unavailable',
    message: string,
    public readonly status: 401 | 503 = 401,
  ) {
    super(message);
    Object.setPrototypeOf(this, EdgeVerificationError.prototype);
  }
}

interface Jwk {
  kid?: string;
  kty?: string;
  n?: string;
  e?: string;
}

export interface CloudflareAccessOptions {
  /** e.g. myteam.cloudflareaccess.com. Comes from configuration only, never from the token. */
  teamDomain: string;
  /** Application Audience (AUD) tag of the Access application. */
  audience: string;
  /** Injectable for tests. */
  fetchImpl?: typeof fetch;
  keyTtlMs?: number;
  /** Minimum gap between forced key refreshes (stops unknown-kid tokens from hammering Cloudflare). */
  refreshCooldownMs?: number;
}

/**
 * Verifies the `Cf-Access-Jwt-Assertion` header against the public keys Cloudflare publishes for your team
 * (https://<team>.cloudflareaccess.com/cdn-cgi/access/certs). Checks signature (RS256 only), issuer, audience
 * and expiry. The `Cf-Access-Authenticated-User-Email` header is never read: it is trivially forgeable
 * by anything that can reach the origin without passing through Cloudflare.
 */
export class CloudflareAccessVerifier implements EdgeIdentityVerifier {
  readonly issuer: string;
  readonly certsUrl: string;
  private keys = new Map<string, KeyObject>();
  private fetchedAt = 0;
  private lastForcedRefresh = 0;
  private inflight: Promise<void> | null = null;
  private readonly fetchImpl: typeof fetch;
  private readonly keyTtlMs: number;
  private readonly cooldownMs: number;

  constructor(private readonly opts: CloudflareAccessOptions) {
    this.issuer = `https://${opts.teamDomain}`;
    this.certsUrl = `${this.issuer}/cdn-cgi/access/certs`;
    this.fetchImpl = opts.fetchImpl ?? fetch;
    this.keyTtlMs = opts.keyTtlMs ?? 60 * 60 * 1000;
    this.cooldownMs = opts.refreshCooldownMs ?? 60 * 1000;
  }

  async verify(headers: Record<string, string | string[] | undefined>): Promise<EdgeIdentity | null> {
    const raw = headers[ACCESS_JWT_HEADER];
    const token = Array.isArray(raw) ? raw[0] : raw;
    if (!token) return null;
    return this.verifyToken(token);
  }

  async verifyToken(token: string): Promise<EdgeIdentity> {
    const decoded = jwt.decode(token, { complete: true });
    const header = decoded && typeof decoded === 'object' ? decoded.header : undefined;
    if (!header || typeof header.kid !== 'string') throw new EdgeVerificationError('malformed', 'Access assertion is malformed');
    if (header.alg !== 'RS256') throw new EdgeVerificationError('invalid_token', 'Unexpected signing algorithm');

    const key = await this.keyFor(header.kid);
    let claims: jwt.JwtPayload;
    try {
      const out = jwt.verify(token, key, { algorithms: ['RS256'], issuer: this.issuer, audience: this.opts.audience });
      if (typeof out === 'string') throw new Error('unexpected payload');
      claims = out;
    } catch (err) {
      throw new EdgeVerificationError('invalid_token', `Access assertion rejected: ${(err as Error).message}`);
    }
    // jsonwebtoken only enforces expiry when the claim exists; an assertion without one is never acceptable.
    if (typeof claims.exp !== 'number') throw new EdgeVerificationError('invalid_token', 'Access assertion has no expiry');

    return {
      provider: 'cloudflare-access',
      email: typeof claims.email === 'string' ? claims.email.toLowerCase() : undefined,
      subject: typeof claims.sub === 'string' ? claims.sub : undefined,
      claims: { iat: claims.iat, exp: claims.exp, type: claims.type, country: claims.country },
    };
  }

  private async keyFor(kid: string): Promise<KeyObject> {
    const now = Date.now();
    const stale = now - this.fetchedAt > this.keyTtlMs;
    if (stale || (!this.keys.has(kid) && now - this.lastForcedRefresh > this.cooldownMs)) {
      if (!stale) this.lastForcedRefresh = now; // unknown kid: Cloudflare may have rotated keys
      await this.refresh().catch((err) => {
        // Keep serving from the previous key set if we have one; otherwise fail closed.
        if (this.keys.size === 0) throw new EdgeVerificationError('keys_unavailable', `Cannot load Cloudflare Access keys: ${(err as Error).message}`, 503);
      });
    }
    const key = this.keys.get(kid);
    if (!key) throw new EdgeVerificationError('unknown_key', 'Access assertion was signed by an unknown key');
    return key;
  }

  private refresh(): Promise<void> {
    this.inflight ??= this.load().finally(() => {
      this.inflight = null;
    });
    return this.inflight;
  }

  private async load(): Promise<void> {
    const res = await this.fetchImpl(this.certsUrl, { signal: AbortSignal.timeout(5000), headers: { accept: 'application/json' } });
    if (!res.ok) throw new Error(`certs endpoint answered ${res.status}`);
    const body = (await res.json()) as { keys?: Jwk[] };
    const next = new Map<string, KeyObject>();
    for (const k of body.keys ?? []) {
      if (k.kty !== 'RSA' || !k.kid || !k.n || !k.e) continue;
      next.set(k.kid, createPublicKey({ key: { kty: 'RSA', n: k.n, e: k.e }, format: 'jwk' }));
    }
    if (next.size === 0) throw new Error('certs endpoint returned no usable RSA keys');
    this.keys = next;
    this.fetchedAt = Date.now();
  }
}
