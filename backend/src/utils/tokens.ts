import jwt, { SignOptions } from 'jsonwebtoken';
import { env } from '../config/env';
import type { Role } from '../modules/user/user.model';

const ISSUER = 'secureshare-zt';
const base = { algorithm: 'HS256', issuer: ISSUER } as const;

export interface AccessPayload extends jwt.JwtPayload {
  sub: string;
  role: Role;
}
export interface RefreshPayload extends jwt.JwtPayload {
  sub: string;
  jti: string;
}

export const signAccessToken = (userId: string, role: Role): string =>
  jwt.sign({ role }, env.JWT_ACCESS_SECRET, {
    ...base,
    subject: userId,
    expiresIn: env.ACCESS_TOKEN_TTL as SignOptions['expiresIn'],
  });

export const signRefreshToken = (userId: string, jti: string): string =>
  jwt.sign({}, env.JWT_REFRESH_SECRET, {
    ...base,
    subject: userId,
    jwtid: jti,
    expiresIn: `${env.REFRESH_TOKEN_TTL_DAYS}d`,
  });

export const verifyAccessToken = (token: string): AccessPayload =>
  jwt.verify(token, env.JWT_ACCESS_SECRET, { algorithms: ['HS256'], issuer: ISSUER }) as AccessPayload;

export const verifyRefreshToken = (token: string): RefreshPayload =>
  jwt.verify(token, env.JWT_REFRESH_SECRET, { algorithms: ['HS256'], issuer: ISSUER }) as RefreshPayload;
