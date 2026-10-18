import 'dotenv/config';
import { z } from 'zod';

/** Treats "" (an empty line in .env) the same as "not set". */
const optional = <T extends z.ZodTypeAny>(inner: T) =>
  z.preprocess((v) => (typeof v === 'string' && v.trim() === '' ? undefined : v), inner.optional());
const flag = z.preprocess((v) => (typeof v === 'string' ? v.trim().toLowerCase() === 'true' : v), z.boolean().default(false));
const TEAM_DOMAIN_RE = /^[a-z0-9-]+\.cloudflareaccess\.com$/;
/** Cloudflare's documented dummy Turnstile secrets (1x/2x/3x...AA). The "always passes" one accepts ANY token. */
const TURNSTILE_DUMMY_SECRET_RE = /^[123]x0+AA$/;
const LOCAL_HOST_RE = /^(localhost|127\.0\.0\.1|\[::1\]|0\.0\.0\.0)$/i;
const lowerOptional = <T extends z.ZodTypeAny>(inner: T) =>
  z.preprocess((v) => (typeof v === 'string' ? (v.trim() === '' ? undefined : v.trim().toLowerCase()) : v), inner.optional());
/** Accepts "myteam", "myteam.cloudflareaccess.com" or a pasted https:// URL. */
const normaliseTeamDomain = (raw: string): string => {
  const host = raw.trim().toLowerCase().replace(/^https?:\/\//, '').replace(/\/.*$/, '');
  return host.includes('.') ? host : `${host}.cloudflareaccess.com`;
};

const schema = z
  .object({
    NODE_ENV: z.enum(['development', 'production', 'test']).default('development'),
    PORT: z.coerce.number().default(5000),
    MONGODB_URI: z.string().min(1),
    CLIENT_URL: z.string().url(),
    JWT_ACCESS_SECRET: z.string().min(32),
    JWT_REFRESH_SECRET: z.string().min(32),
    ACCESS_TOKEN_TTL: z.string().default('15m'),
    REFRESH_TOKEN_TTL_DAYS: z.coerce.number().int().positive().default(7),
    BCRYPT_ROUNDS: z.coerce.number().int().min(10).max(15).default(12),

    // Email (Brevo transactional API). Key optional in dev, required in production.
    BREVO_API_KEY: z.string().trim().optional(),
    EMAIL_FROM_NAME: z.string().trim().min(1).default('SecureShare ZT'),
    EMAIL_FROM_ADDRESS: z.string().trim().email().optional().or(z.literal('').transform(() => undefined)),

    // Storage. Local disk by default; no cloud credentials are needed to boot.
    STORAGE_PROVIDER: z.enum(['local']).default('local'),
    UPLOAD_DIR: z.string().trim().min(1).default('uploads'),
    MAX_UPLOAD_MB: z.coerce.number().int().min(1).max(100).default(25),

    // ---- Phase 3: tunnel + Cloudflare Access (all optional; local dev needs none of them) ----
    /** Extra exact origins allowed by CORS, comma separated. CLIENT_URL is always allowed. */
    ALLOWED_ORIGINS: optional(z.string()),
    /** Number of reverse proxies in front of the API (req.ip / X-Forwarded-For trust). */
    TRUST_PROXY_HOPS: z.coerce.number().int().min(0).max(5).default(1),
    /** Informational only: the Quick Tunnel URL you started by hand. Never auto-detected. */
    TUNNEL_PUBLIC_URL: optional(z.string().url()),
    /** When true, every /api/v1 request must carry a valid Cloudflare Access JWT. */
    CLOUDFLARE_ACCESS_ENABLED: flag,
    CF_ACCESS_TEAM_DOMAIN: optional(z.string().trim()),
    CF_ACCESS_AUD: optional(z.string().trim()),

    // ---- Security hardening ----
    /** Cloudflare Turnstile secret key. Server-side only: never exposed to the browser. Required in production. */
    TURNSTILE_SECRET_KEY: optional(z.string().trim()),
    /** Optional override: hostnames Turnstile may report (comma separated). Default: hostnames of CLIENT_URL + ALLOWED_ORIGINS. */
    TURNSTILE_EXPECTED_HOSTNAMES: optional(z.string()),
    /** Where rate-limit counters live. "memory" is per-process and resets on restart; "mongo" is shared and survives restarts. */
    RATE_LIMIT_STORE: z.preprocess(
      (v) => (typeof v === 'string' ? (v.trim() === '' ? undefined : v.trim().toLowerCase()) : v),
      z.enum(['memory', 'mongo']).default('memory'),
    ),
    /** Trusted header carrying the real client IP (set by Cloudflare). Leave unset unless you verified it for your host. */
    CLIENT_IP_HEADER: lowerOptional(z.enum(['cf-connecting-ip', 'true-client-ip'])),
    /** When set, every request except /health must carry this value in X-Origin-Verify (set by a Cloudflare Transform Rule). */
    ORIGIN_VERIFY_SECRET: optional(z.string().min(32, 'Use at least 32 characters')),
  })
  .superRefine((v, ctx) => {
    if (v.NODE_ENV === 'production') {
      if (!v.BREVO_API_KEY) ctx.addIssue({ code: 'custom', path: ['BREVO_API_KEY'], message: 'Required in production' });
      if (!v.EMAIL_FROM_ADDRESS) ctx.addIssue({ code: 'custom', path: ['EMAIL_FROM_ADDRESS'], message: 'Required in production' });
      // Fail closed: production never boots without a real Turnstile secret.
      if (!v.TURNSTILE_SECRET_KEY) {
        ctx.addIssue({ code: 'custom', path: ['TURNSTILE_SECRET_KEY'], message: 'Required in production (Cloudflare Turnstile secret key)' });
      } else if (TURNSTILE_DUMMY_SECRET_RE.test(v.TURNSTILE_SECRET_KEY)) {
        ctx.addIssue({ code: 'custom', path: ['TURNSTILE_SECRET_KEY'], message: 'Cloudflare dummy test secrets accept any token and must not be used in production' });
      }
      // Production CORS: exact https origins only, never localhost.
      const prodOrigins: [string, string][] = [
        ['CLIENT_URL', v.CLIENT_URL],
        ...(v.ALLOWED_ORIGINS ?? '').split(',').map((x) => x.trim()).filter(Boolean).map((o): [string, string] => ['ALLOWED_ORIGINS', o]),
      ];
      for (const [path, raw] of prodOrigins) {
        try {
          const u = new URL(raw.replace(/\/+$/, ''));
          if (u.protocol !== 'https:' || LOCAL_HOST_RE.test(u.hostname) || u.origin !== raw.replace(/\/+$/, '')) throw new Error();
        } catch {
          ctx.addIssue({ code: 'custom', path: [path], message: `"${raw}" is not allowed in production: use an exact https origin (no localhost, no path)` });
        }
      }
    }
    for (const h of (v.TURNSTILE_EXPECTED_HOSTNAMES ?? '').split(',').map((x) => x.trim()).filter(Boolean)) {
      if (!/^[a-z0-9.-]+$/i.test(h)) ctx.addIssue({ code: 'custom', path: ['TURNSTILE_EXPECTED_HOSTNAMES'], message: `"${h}" is not a hostname` });
    }
    if (v.CF_ACCESS_TEAM_DOMAIN && !TEAM_DOMAIN_RE.test(normaliseTeamDomain(v.CF_ACCESS_TEAM_DOMAIN))) {
      ctx.addIssue({ code: 'custom', path: ['CF_ACCESS_TEAM_DOMAIN'], message: 'Expected <team>.cloudflareaccess.com' });
    }
    if (v.CLOUDFLARE_ACCESS_ENABLED) {
      // Never boot with Access "enabled" but unable to verify anything.
      if (!v.CF_ACCESS_TEAM_DOMAIN) ctx.addIssue({ code: 'custom', path: ['CF_ACCESS_TEAM_DOMAIN'], message: 'Required when CLOUDFLARE_ACCESS_ENABLED=true' });
      if (!v.CF_ACCESS_AUD) ctx.addIssue({ code: 'custom', path: ['CF_ACCESS_AUD'], message: 'Required when CLOUDFLARE_ACCESS_ENABLED=true' });
    }
    for (const o of (v.ALLOWED_ORIGINS ?? '').split(',').map((x) => x.trim()).filter(Boolean)) {
      try {
        if (new URL(o).origin !== o) throw new Error();
      } catch {
        ctx.addIssue({ code: 'custom', path: ['ALLOWED_ORIGINS'], message: `"${o}" is not an exact origin (e.g. https://example.trycloudflare.com, no path or trailing slash)` });
      }
    }
  });

const parsed = schema.safeParse(process.env);
if (!parsed.success) {
  // Fail fast: never boot with a partial security configuration.
  console.error('Invalid environment configuration:', parsed.error.flatten().fieldErrors);
  process.exit(1);
}
if (parsed.data.JWT_ACCESS_SECRET === parsed.data.JWT_REFRESH_SECRET) {
  console.error('JWT_ACCESS_SECRET and JWT_REFRESH_SECRET must differ');
  process.exit(1);
}

const teamDomain = parsed.data.CF_ACCESS_TEAM_DOMAIN ? normaliseTeamDomain(parsed.data.CF_ACCESS_TEAM_DOMAIN) : undefined;
const stripSlash = (u: string) => u.replace(/\/+$/, '');

const allowedOrigins = [
  ...new Set(
    [parsed.data.CLIENT_URL, ...(parsed.data.ALLOWED_ORIGINS ?? '').split(',')].map((x) => stripSlash(x.trim())).filter(Boolean),
  ),
];
const turnstileSecret = parsed.data.TURNSTILE_SECRET_KEY;
const explicitHosts = (parsed.data.TURNSTILE_EXPECTED_HOSTNAMES ?? '').split(',').map((x) => x.trim().toLowerCase()).filter(Boolean);

export const env = {
  ...parsed.data,
  isProd: parsed.data.NODE_ENV === 'production',
  /** Exact origins CORS accepts: CLIENT_URL plus ALLOWED_ORIGINS. */
  allowedOrigins,
  turnstile: {
    /** Verification is enforced whenever a secret is configured (always, in production: boot fails otherwise). */
    enabled: !!turnstileSecret,
    secret: turnstileSecret,
    /** Cloudflare test secret: hostname/action checks are skipped because test tokens do not carry real ones. */
    dummy: !!turnstileSecret && TURNSTILE_DUMMY_SECRET_RE.test(turnstileSecret),
    expectedHostnames: explicitHosts.length ? explicitHosts : [...new Set(allowedOrigins.map((o) => new URL(o).hostname.toLowerCase()))],
  },
  cloudflareAccess: {
    enabled: parsed.data.CLOUDFLARE_ACCESS_ENABLED,
    /** True when both values needed to verify an assertion are present. */
    configured: !!(teamDomain && parsed.data.CF_ACCESS_AUD),
    teamDomain,
    aud: parsed.data.CF_ACCESS_AUD,
  },
};
