import { Router } from 'express';
import {
  loginAccountLimiter, loginLimiter, passwordResetEmailLimiter, passwordResetLimiter, refreshLimiter, registerLimiter,
  resendVerificationEmailLimiter, resendVerificationLimiter, resetPasswordLimiter, verifyEmailLimiter,
} from '../../middleware/rateLimiter';
import { requireXhrHeader } from '../../middleware/auth';
import { requireTurnstile } from '../../middleware/turnstile';
import { validate } from '../../middleware/validate';
import { authController as c } from './auth.controller';
import {
  emailOnlySchema, forgotPasswordSchema, loginSchema, registerSchema, resetPasswordSchema, tokenSchema,
} from './auth.validation';

const router = Router();

// Order everywhere: cheap rate limits -> input validation -> Turnstile (a network call) -> controller.
router.post('/register', registerLimiter, validate(registerSchema), requireTurnstile('register'), c.register);
router.post('/verify-email', verifyEmailLimiter, validate(tokenSchema), c.verifyEmail);
// No form calls this yet; it sends email, so it is rate limited per client and per target address.
router.post('/resend-verification', resendVerificationLimiter, resendVerificationEmailLimiter, validate(emailOnlySchema), c.resendVerification);
router.post('/login', loginLimiter, loginAccountLimiter, validate(loginSchema), requireTurnstile('login'), c.login);
router.post('/forgot-password', passwordResetLimiter, passwordResetEmailLimiter, validate(forgotPasswordSchema), requireTurnstile('forgot-password'), c.forgotPassword);
router.post('/reset-password', resetPasswordLimiter, validate(resetPasswordSchema), requireTurnstile('reset-password'), c.resetPassword);

// Cookie-authenticated endpoints require the CSRF header.
router.post('/refresh', refreshLimiter, requireXhrHeader, c.refresh);
router.post('/logout', requireXhrHeader, c.logout);

export default router;
