import { RequestHandler } from 'express';
import { SYSTEM_TARGET_ID, auditService } from '../modules/audit/audit.service';
import { AppError } from '../utils/AppError';
import { logger } from '../utils/logger';
import { TurnstileAction, TurnstileRejection, verifyTurnstile } from '../services/turnstile.service';

/**
 * Requires a valid Turnstile token in `body.turnstileToken` for the given form. Mount it AFTER the request body has been
 * validated and BEFORE the controller. The token is removed from the body so it can never reach services or the database.
 */
export const requireTurnstile =
  (action: TurnstileAction): RequestHandler =>
  async (req, _res, next) => {
    const token = req.body?.turnstileToken;
    if (req.body && typeof req.body === 'object') delete req.body.turnstileToken;
    try {
      await verifyTurnstile({ token, action, ip: req.ip });
      next();
    } catch (err) {
      if (!(err instanceof TurnstileRejection)) return next(err);
      logger.warn('Turnstile verification rejected', { action, reason: err.reason, ip: req.ip });
      // Best effort and never blocking: the audit row carries the reason code only, never the token.
      void Promise.resolve(
        auditService.record({ ip: req.ip, userAgent: req.get('user-agent')?.slice(0, 300) }, 'TURNSTILE_FAILED', 'system', SYSTEM_TARGET_ID, {
          action, reason: err.reason, status: err.status,
        }),
      ).catch((e) => logger.error('Turnstile audit write failed', { err: e }));
      next(new AppError(err.publicMessage, err.status, true, err.code));
    }
  };
