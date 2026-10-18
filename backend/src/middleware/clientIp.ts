import { RequestHandler } from 'express';
import { env } from '../config/env';
import { parseSingleIp } from '../utils/ip';
import { logger } from '../utils/logger';

let warnedMissing = false;

/**
 * Optional: take req.ip from a header that a trusted edge (Cloudflare) overwrites, instead of from X-Forwarded-For.
 *
 * Why: on Render the X-Forwarded-For chain keeps whatever the client sent and then appends the real IP plus edge/internal
 * hops (community-measured, not in Render's docs), so `trust proxy = N` can resolve every visitor to a shared edge IP.
 * Leave CLIENT_IP_HEADER unset to keep the plain `trust proxy` behaviour. Only enable it after verifying with the
 * procedure in docs/SECURITY-HARDENING.md. A request that does not carry exactly one valid IP in that header falls back
 * to Express's own value; lists, ports and garbage are ignored.
 *
 * This is only safe if clients cannot reach the app without passing through the edge that sets the header.
 */
export const clientIp: RequestHandler = (req, _res, next) => {
  const header = env.CLIENT_IP_HEADER;
  if (header) {
    const ip = parseSingleIp(req.headers[header]);
    if (ip) {
      // req.ip is a prototype getter in Express 4; an own property shadows it for everything downstream
      // (rate limiting, audit log, access log).
      Object.defineProperty(req, 'ip', { value: ip, configurable: true, enumerable: true, writable: true });
    } else if (!warnedMissing && env.isProd) {
      warnedMissing = true;
      logger.warn(`CLIENT_IP_HEADER=${header} is set but a request arrived without a valid value; falling back to trust-proxy IP`);
    }
  }
  next();
};
