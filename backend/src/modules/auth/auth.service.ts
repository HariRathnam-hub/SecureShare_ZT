import bcrypt from 'bcrypt';
import { env } from '../../config/env';
import { AppError } from '../../utils/AppError';
import { randomToken, sha256 } from '../../utils/crypto';
import { logger } from '../../utils/logger';
import { signAccessToken, signRefreshToken, verifyRefreshToken } from '../../utils/tokens';
import { emailService } from '../../services/email.service';
import { isKnownUserAgent, uaHash } from '../../security/signals';
import { auditService, SYSTEM_TARGET_ID } from '../audit/audit.service';
import { User, UserDocument } from '../user/user.model';
import type { LoginInput, RegisterInput } from './auth.validation';

export interface ClientMeta {
  ip?: string;
  userAgent?: string;
}
export interface AuthResult {
  user: UserDocument;
  accessToken: string;
  refreshToken: string;
}

const MAX_SESSIONS = 10;

/** Security audit writes must never turn a normal auth response into a 500. */
async function auditSafe(...args: Parameters<typeof auditService.record>): Promise<void> {
  try {
    await auditService.record(...args);
  } catch (err) {
    logger.error('Security audit write failed', { action: args[1], err });
  }
}
const actorMeta = (id: string, meta: ClientMeta) => ({ id, ip: meta.ip, userAgent: meta.userAgent?.slice(0, 300) });
const DAY = 86_400_000;
// Used to equalise response time when the email is unknown (anti user-enumeration).
const DUMMY_HASH = bcrypt.hashSync('timing-equaliser', env.BCRYPT_ROUNDS);

async function issueTokens(user: UserDocument, meta: ClientMeta): Promise<AuthResult> {
  const id = String(user._id);
  const refreshToken = signRefreshToken(id, randomToken(16));
  const now = Date.now();
  await User.updateOne(
    { _id: user._id },
    {
      $push: {
        refreshTokens: {
          $each: [
            {
              tokenHash: sha256(refreshToken),
              expiresAt: new Date(now + env.REFRESH_TOKEN_TTL_DAYS * DAY),
              createdAt: new Date(now),
              userAgent: meta.userAgent?.slice(0, 300),
              ip: meta.ip,
            },
          ],
          $slice: -MAX_SESSIONS, // oldest sessions fall off
        },
      },
    },
  );
  return { user, accessToken: signAccessToken(id, user.role), refreshToken };
}

export const authService = {
  async register(input: RegisterInput): Promise<void> {
    const existing = await User.exists({ email: input.email });
    if (existing) {
      // Respond identically to a fresh signup so emails cannot be enumerated.
      logger.info('Registration attempted for existing email');
      return;
    }
    const raw = randomToken();
    const user = await User.create({
      ...input,
      emailVerificationToken: sha256(raw),
      emailVerificationExpires: new Date(Date.now() + DAY),
    });
    await emailService.sendVerification(user.email, user.name, raw);
    logger.info('User registered', { userId: user.id });
  },

  async verifyEmail(token: string): Promise<void> {
    const user = await User.findOne({
      emailVerificationToken: sha256(token),
      emailVerificationExpires: { $gt: new Date() },
    }).select('+emailVerificationToken +emailVerificationExpires');
    if (!user) throw new AppError('Verification link is invalid or has expired', 400);
    user.isEmailVerified = true;
    user.emailVerificationToken = undefined;
    user.emailVerificationExpires = undefined;
    await user.save();
    logger.info('Email verified', { userId: user.id });
  },

  async resendVerification(email: string): Promise<void> {
    const user = await User.findOne({ email, isEmailVerified: false });
    if (!user) return;
    const raw = randomToken();
    user.emailVerificationToken = sha256(raw);
    user.emailVerificationExpires = new Date(Date.now() + DAY);
    await user.save();
    await emailService.sendVerification(user.email, user.name, raw);
  },

  async login({ email, password }: LoginInput, meta: ClientMeta): Promise<AuthResult> {
    const user = await User.findOne({ email }).select('+password');
    const valid = user ? await user.comparePassword(password) : await bcrypt.compare(password, DUMMY_HASH);
    if (!user || !valid) {
      logger.warn('Failed login', { email, ip: meta.ip });
      // Attributed to the targeted account when it exists; unknown emails are grouped by a hash, never stored.
      await auditSafe(
        user ? actorMeta(user.id, meta) : { ip: meta.ip, userAgent: meta.userAgent?.slice(0, 300) },
        'LOGIN_FAILED', user ? 'user' : 'system', user ? user._id : SYSTEM_TARGET_ID,
        { reason: 'invalid_credentials', knownAccount: !!user, ...(user ? {} : { emailHash: sha256(email).slice(0, 16) }) },
      );
      throw new AppError('Invalid email or password', 401);
    }
    if (!user.isActive) {
      await auditSafe(actorMeta(user.id, meta), 'LOGIN_FAILED', 'user', user._id, { reason: 'account_disabled', knownAccount: true });
      throw new AppError('This account has been disabled', 403);
    }
    if (!user.isEmailVerified) throw new AppError('Verify your email before signing in', 403);

    // Housekeeping: drop expired refresh tokens.
    await User.updateOne({ _id: user._id }, { $pull: { refreshTokens: { expiresAt: { $lt: new Date() } } } });
    await User.updateOne({ _id: user._id }, { lastLoginAt: new Date() });
    logger.info('Login success', { userId: user.id, ip: meta.ip });
    // Computed before issueTokens() stores this session's user agent. A weak heuristic, recorded for review only.
    const newDevice = !(await isKnownUserAgent(user.id, meta.userAgent).catch(() => true));
    await auditSafe(actorMeta(user.id, meta), 'LOGIN_SUCCESS', 'user', user._id, { uaHash: uaHash(meta.userAgent), newDevice });
    return issueTokens(user, meta);
  },

  /** Rotating refresh with reuse detection. */
  async refresh(token: string | undefined, meta: ClientMeta): Promise<AuthResult> {
    if (!token) throw new AppError('Session expired', 401);
    let payload;
    try {
      payload = verifyRefreshToken(token);
    } catch {
      throw new AppError('Session expired', 401);
    }
    const tokenHash = sha256(token);
    // Atomic: only one concurrent request can consume a given refresh token.
    const user = await User.findOneAndUpdate(
      { _id: payload.sub, 'refreshTokens.tokenHash': tokenHash },
      { $pull: { refreshTokens: { tokenHash } } },
      { new: false },
    );
    if (!user) {
      // Valid signature but unknown hash => token already used or revoked: assume theft.
      await User.updateOne({ _id: payload.sub }, { $set: { refreshTokens: [] } });
      logger.warn('Refresh token reuse detected; all sessions revoked', { userId: payload.sub, ip: meta.ip });
      await auditSafe(actorMeta(payload.sub, meta), 'SESSION_REVOKED', 'user', payload.sub, { reason: 'refresh_token_reuse' });
      throw new AppError('Session expired', 401);
    }
    if (!user.isActive) throw new AppError('This account has been disabled', 403);
    return issueTokens(user, meta);
  },

  async logout(token: string | undefined): Promise<void> {
    if (!token) return;
    try {
      const { sub } = verifyRefreshToken(token);
      await User.updateOne({ _id: sub }, { $pull: { refreshTokens: { tokenHash: sha256(token) } } });
      logger.info('Logout', { userId: sub });
    } catch {
      /* already invalid: nothing to revoke */
    }
  },

  async forgotPassword(email: string): Promise<void> {
    const user = await User.findOne({ email, isActive: true });
    if (!user) return; // identical response either way
    const raw = randomToken();
    user.passwordResetToken = sha256(raw);
    user.passwordResetExpires = new Date(Date.now() + 60 * 60 * 1000);
    await user.save();
    await emailService.sendPasswordReset(user.email, user.name, raw);
    logger.info('Password reset requested', { userId: user.id });
  },

  async resetPassword(token: string, password: string): Promise<void> {
    const user = await User.findOne({
      passwordResetToken: sha256(token),
      passwordResetExpires: { $gt: new Date() },
    }).select('+passwordResetToken +passwordResetExpires +refreshTokens');
    if (!user) throw new AppError('Reset link is invalid or has expired', 400);
    user.password = password; // hashed + passwordChangedAt set in pre-save hook
    user.passwordResetToken = undefined;
    user.passwordResetExpires = undefined;
    user.refreshTokens = []; // revoke every session on credential change
    await user.save();
    logger.info('Password reset completed', { userId: user.id });
    await auditSafe({ id: user.id }, 'SESSION_REVOKED', 'user', user.id, { reason: 'password_reset' });
  },
};
