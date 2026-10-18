import { CookieOptions, Request, Response } from 'express';
import { env } from '../../config/env';
import { asyncHandler } from '../../utils/asyncHandler';
import { authService, AuthResult } from './auth.service';

export const REFRESH_COOKIE = 'szt_rt';

const cookieOptions: CookieOptions = {
  httpOnly: true,
  secure: env.isProd,
  // Frontend (Vercel) and API (Render) are different sites in production.
  sameSite: env.isProd ? 'none' : 'lax',
  path: '/api/v1/auth',
};

const meta = (req: Request) => ({ ip: req.ip, userAgent: req.get('user-agent') });

function sendSession(res: Response, result: AuthResult, status = 200) {
  res.cookie(REFRESH_COOKIE, result.refreshToken, {
    ...cookieOptions,
    maxAge: env.REFRESH_TOKEN_TTL_DAYS * 86_400_000,
  });
  res.setHeader('Cache-Control', 'no-store');
  res.status(status).json({ status: 'success', data: { user: result.user, accessToken: result.accessToken } });
}

const generic = (message: string) => (_req: Request, res: Response) =>
  res.status(200).json({ status: 'success', message });

export const authController = {
  register: asyncHandler(async (req, res) => {
    await authService.register(req.body);
    res.status(201).json({
      status: 'success',
      message: 'If this email can be registered, a verification link is on its way.',
    });
  }),

  verifyEmail: asyncHandler(async (req, res) => {
    await authService.verifyEmail(req.body.token);
    res.json({ status: 'success', message: 'Email verified. You can now sign in.' });
  }),

  resendVerification: asyncHandler(async (req, res) => {
    await authService.resendVerification(req.body.email);
    generic('If the account needs verification, a new link has been sent.')(req, res);
  }),

  login: asyncHandler(async (req, res) => sendSession(res, await authService.login(req.body, meta(req)))),

  refresh: asyncHandler(async (req, res) =>
    sendSession(res, await authService.refresh(req.cookies?.[REFRESH_COOKIE], meta(req))),
  ),

  logout: asyncHandler(async (req, res) => {
    await authService.logout(req.cookies?.[REFRESH_COOKIE]);
    res.clearCookie(REFRESH_COOKIE, cookieOptions);
    res.status(204).end();
  }),

  forgotPassword: asyncHandler(async (req, res) => {
    await authService.forgotPassword(req.body.email);
    generic('If an account exists for that email, a reset link has been sent.')(req, res);
  }),

  resetPassword: asyncHandler(async (req, res) => {
    await authService.resetPassword(req.body.token, req.body.password);
    res.json({ status: 'success', message: 'Password updated. Sign in with your new password.' });
  }),
};
