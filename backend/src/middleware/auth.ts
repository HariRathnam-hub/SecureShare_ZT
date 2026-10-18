import { RequestHandler } from 'express';
import { AppError } from '../utils/AppError';
import { asyncHandler } from '../utils/asyncHandler';
import { verifyAccessToken } from '../utils/tokens';
import { Role, User } from '../modules/user/user.model';

/**
 * Zero Trust: the JWT only proves who is asking. Account state and role are
 * re-read from the database on every request, so bans, role changes and
 * password resets take effect immediately.
 */
export const authenticate: RequestHandler = asyncHandler(async (req, _res, next) => {
  const header = req.headers.authorization;
  if (!header?.startsWith('Bearer ')) throw new AppError('Authentication required', 401);

  let payload;
  try {
    payload = verifyAccessToken(header.slice(7));
  } catch {
    throw new AppError('Invalid or expired token', 401);
  }

  const user = await User.findById(payload.sub);
  if (!user) throw new AppError('Invalid or expired token', 401);
  if (!user.isActive) throw new AppError('This account has been disabled', 403);
  if (user.passwordChangedAt && (payload.iat ?? 0) < Math.floor(user.passwordChangedAt.getTime() / 1000)) {
    throw new AppError('Session expired, please sign in again', 401);
  }

  req.user = { id: user.id, email: user.email, role: user.role };
  next();
});

/** RBAC gate. Always place after `authenticate`. */
export const authorize =
  (...roles: Role[]): RequestHandler =>
  (req, _res, next) => {
    if (!req.user) return next(new AppError('Authentication required', 401));
    if (!roles.includes(req.user.role)) return next(new AppError('You do not have permission to do this', 403));
    next();
  };

/** CSRF defence for cookie-authenticated endpoints: forces a CORS preflight. */
export const requireXhrHeader: RequestHandler = (req, _res, next) => {
  if (req.get('x-requested-with') !== 'XMLHttpRequest') {
    return next(new AppError('Invalid request', 403));
  }
  next();
};
