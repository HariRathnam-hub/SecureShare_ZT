import winston from 'winston';
import { env } from '../config/env';

const { combine, timestamp, errors, json, colorize, printf } = winston.format;

const devFormat = combine(
  colorize(),
  timestamp({ format: 'HH:mm:ss' }),
  errors({ stack: true }),
  printf(({ level, message, timestamp: ts, stack, ...meta }) => {
    const rest = Object.keys(meta).length ? ` ${JSON.stringify(meta)}` : '';
    return `${ts} ${level}: ${stack ?? message}${rest}`;
  }),
);

export const logger = winston.createLogger({
  level: env.isProd ? 'info' : 'debug',
  format: env.isProd ? combine(timestamp(), errors({ stack: true }), json()) : devFormat,
  transports: [
    new winston.transports.Console(),
    // Render's filesystem is ephemeral; files are for local development only.
    ...(env.isProd
      ? []
      : [new winston.transports.File({ filename: 'logs/error.log', level: 'error' })]),
  ],
});
