import cookieParser from 'cookie-parser';
import cors from 'cors';
import express from 'express';
import helmet from 'helmet';
import { env } from './config/env';
import { errorHandler, notFound } from './middleware/errorHandler';
import { clientIp } from './middleware/clientIp';
import { cloudflareAccessGate } from './middleware/cloudflareAccess';
import { originVerify } from './middleware/originVerify';
import { globalLimiter } from './middleware/rateLimiter';
import authRoutes from './modules/auth/auth.routes';
import userRoutes from './modules/user/user.routes';
import accessRequestRoutes from './modules/access-requests/access-request.routes';
import auditRoutes from './modules/audit/audit.routes';
import fileRoutes from './modules/files/file.routes';
import linkRoutes from './modules/links/link.routes';
import roomRoutes from './modules/rooms/room.routes';
import securityRoutes from './modules/security/security.routes';
import { logger } from './utils/logger';

export const app = express();

app.disable('x-powered-by');
app.set('trust proxy', env.TRUST_PROXY_HOPS); // number of reverse proxies in front of the API; drives req.ip unless CLIENT_IP_HEADER is set
app.use(clientIp); // optional: real client IP from a header the edge overwrites (see docs/SECURITY-HARDENING.md)

app.use(
  helmet({
    contentSecurityPolicy: { directives: { defaultSrc: ["'none'"], frameAncestors: ["'none'"] } },
    hsts: { maxAge: 31_536_000, includeSubDomains: true, preload: true },
    referrerPolicy: { policy: 'no-referrer' },
    crossOriginResourcePolicy: { policy: 'same-site' },
  }),
);

app.use(originVerify); // optional origin lock: a pass-through unless ORIGIN_VERIFY_SECRET is set

app.use(
  cors({
    // Exact-match allow-list (CLIENT_URL + ALLOWED_ORIGINS). Requests without an Origin header (curl, server-to-server) are not
    // a CORS concern; cookie-authenticated routes are protected separately by the X-Requested-With check.
    origin: (origin, cb) => (!origin || env.allowedOrigins.includes(origin) ? cb(null, true) : cb(new Error('CORS: origin not allowed'))),
    credentials: true,
    methods: ['GET', 'POST', 'PATCH', 'DELETE'],
    allowedHeaders: ['Content-Type', 'Authorization', 'X-Requested-With'],
    // Lets the browser app read how long to wait after a 429, and the download metadata headers.
    exposedHeaders: ['Retry-After', 'Content-Disposition', 'X-Download-Id'],
    maxAge: 600,
  }),
);

app.use(express.json({ limit: '10kb' }));
app.use(cookieParser());
app.use(globalLimiter);

app.use((req, res, next) => {
  const start = Date.now();
  res.on('finish', () =>
    logger.info(`${req.method} ${req.originalUrl} ${res.statusCode} ${Date.now() - start}ms`, { ip: req.ip }),
  );
  next();
});

app.get('/health', (_req, res) => res.json({ status: 'ok', uptime: process.uptime() }));
// Optional Cloudflare Access gate: a pass-through unless CLOUDFLARE_ACCESS_ENABLED=true. /health stays open for platform probes.
app.use('/api/v1', cloudflareAccessGate);
app.use('/api/v1/auth', authRoutes);
app.use('/api/v1/users', userRoutes);
// Phase 2
app.use('/api/v1/files', fileRoutes);
app.use('/api/v1/links', linkRoutes);
app.use('/api/v1/access-requests', accessRequestRoutes);
app.use('/api/v1/rooms', roomRoutes);
app.use('/api/v1/audit', auditRoutes);
// Phase 3
app.use('/api/v1/security', securityRoutes);

app.use(notFound);
app.use(errorHandler);
