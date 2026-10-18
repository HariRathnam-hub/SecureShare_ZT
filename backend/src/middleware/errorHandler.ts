import { ErrorRequestHandler, RequestHandler } from 'express';
import { ZodError } from 'zod';
import { env } from '../config/env';
import { AppError } from '../utils/AppError';
import { logger } from '../utils/logger';

export const notFound: RequestHandler = (req, _res, next) =>
  next(new AppError(`Route not found: ${req.method} ${req.originalUrl}`, 404));

export const errorHandler: ErrorRequestHandler = (err, req, res, _next) => {
  let status = 500;
  let message = 'Something went wrong';
  let details: unknown;
  let code: string | undefined;

  if (err instanceof AppError) {
    status = err.statusCode;
    message = err.message;
    code = err.code;
  } else if (err instanceof ZodError) {
    status = 400;
    message = 'Validation failed';
    details = err.flatten().fieldErrors;
  } else if (err?.code === 11000) {
    status = 409;
    message = 'Resource already exists';
  } else if (err?.name === 'CastError') {
    status = 400;
    message = 'Invalid identifier';
  } else if (err?.type === 'entity.parse.failed') {
    status = 400;
    message = 'Malformed JSON body';
  } else if (err?.message?.startsWith('CORS')) {
    status = 403;
    message = 'Origin not allowed';
  }

  const log = status >= 500 ? logger.error.bind(logger) : logger.warn.bind(logger);
  log(`${req.method} ${req.originalUrl} -> ${status}`, {
    message: err?.message,
    userId: req.user?.id,
    ip: req.ip,
    ...(status >= 500 && { stack: err?.stack }),
  });

  res.status(status).json({
    status: 'error',
    message,
    ...(code ? { code } : {}),
    ...(details ? { errors: details } : {}),
    ...(!env.isProd && status >= 500 ? { stack: err?.stack } : {}),
  });
};
