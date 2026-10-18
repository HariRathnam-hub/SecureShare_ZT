import { app } from './app';
import { connectDB, disconnectDB } from './config/db';
import { env } from './config/env';
import { ensureRateLimitIndexes } from './middleware/mongoRateLimitStore';
import { getStorage } from './storage';
import { logger } from './utils/logger';

async function bootstrap() {
  await connectDB();
  // Production runs with autoIndex off, so the TTL index for shared rate-limit counters is created explicitly.
  if (env.RATE_LIMIT_STORE === 'mongo') await ensureRateLimitIndexes();
  // Fail fast if the upload directory is not writable (no cloud credentials involved).
  await getStorage().healthCheck?.();
  // Effective security configuration, without any secret values. Check this after every deploy.
  logger.info('Security configuration', {
    corsOrigins: env.allowedOrigins,
    turnstile: env.turnstile.enabled ? (env.turnstile.dummy ? 'dummy-test-secret' : 'enforced') : 'skipped (development only)',
    rateLimitStore: env.RATE_LIMIT_STORE,
    clientIpSource: env.CLIENT_IP_HEADER ?? `x-forwarded-for (trust proxy hops=${env.TRUST_PROXY_HOPS})`,
    originLock: !!env.ORIGIN_VERIFY_SECRET,
    cloudflareAccess: env.cloudflareAccess.enabled,
  });
  if (env.isProd && env.RATE_LIMIT_STORE === 'memory') {
    logger.warn('RATE_LIMIT_STORE=memory: rate-limit counters are per process and reset on every restart or spin-down. Set RATE_LIMIT_STORE=mongo for shared counters.');
  }
  const server = app.listen(env.PORT, () => logger.info(`API listening on :${env.PORT} (${env.NODE_ENV})`));

  const shutdown = async (signal: string) => {
    logger.info(`${signal} received, shutting down`);
    server.close(async () => {
      await disconnectDB();
      process.exit(0);
    });
    setTimeout(() => process.exit(1), 10_000).unref();
  };
  process.on('SIGTERM', () => shutdown('SIGTERM'));
  process.on('SIGINT', () => shutdown('SIGINT'));
}

process.on('unhandledRejection', (reason) => {
  logger.error('Unhandled rejection', { reason });
  process.exit(1);
});
process.on('uncaughtException', (err) => {
  logger.error('Uncaught exception', { err });
  process.exit(1);
});

bootstrap().catch((err) => {
  logger.error('Failed to start', { err });
  process.exit(1);
});
