import { createHash } from 'crypto';
import { AuditLog } from '../modules/audit/audit-log.model';
import { User } from '../modules/user/user.model';
import { levelOf, REASON, RISK } from './policy';
import type { AccessSignals, DeviceAssessment, DeviceTrustProvider, RiskAssessment, RiskEngine } from './types';

const UA_MAX = 300; // same cut-off the auth and audit code apply when storing a user agent

/** Stable, non-reversible handle for a user-agent string (stored in audit metadata instead of the raw value). */
export const uaHash = (userAgent?: string): string | undefined =>
  userAgent ? createHash('sha256').update(userAgent.slice(0, UA_MAX)).digest('hex').slice(0, 32) : undefined;

/**
 * "Known" means this account has previously signed in or refreshed with the same user-agent string:
 * either a live session carries it, or an earlier LOGIN_SUCCESS audit record does. This is a weak,
 * spoofable heuristic, not device identity.
 */
export async function isKnownUserAgent(userId: string, userAgent?: string): Promise<boolean> {
  if (!userAgent) return false;
  const ua = userAgent.slice(0, UA_MAX);
  const user = await User.findById(userId).select('+refreshTokens').lean();
  const now = new Date();
  if (user?.refreshTokens?.some((t) => t.expiresAt > now && t.userAgent === ua)) return true;
  return !!(await AuditLog.exists({ actor: userId, action: 'LOGIN_SUCCESS', 'metadata.uaHash': uaHash(ua) }));
}

export const userAgentDeviceTrust: DeviceTrustProvider = {
  async assess(signals: AccessSignals): Promise<DeviceAssessment> {
    const known = await isKnownUserAgent(signals.userId, signals.userAgent);
    return {
      trusted: known,
      deviceId: uaHash(signals.userAgent),
      reasons: known ? [] : [signals.userAgent ? 'user_agent_not_seen_before' : 'no_user_agent'],
    };
  },
};

/** Risk from signals the platform already records: sessions, failed logins and download volume. */
export const dbRiskEngine: RiskEngine = {
  async assess(signals: AccessSignals): Promise<RiskAssessment> {
    const now = Date.now();
    const [user, failedLogins, downloads] = await Promise.all([
      User.findById(signals.userId).select('+refreshTokens').lean(),
      AuditLog.countDocuments({
        action: 'LOGIN_FAILED', targetType: 'user', targetId: signals.userId,
        timestamp: { $gte: new Date(now - RISK.windows.failedLoginsMs) },
      }),
      AuditLog.countDocuments({
        action: 'DOWNLOAD_FILE', actor: signals.userId,
        timestamp: { $gte: new Date(now - RISK.windows.downloadsMs) },
      }),
    ]);
    if (!user) throw new Error('user not found during risk assessment');

    let score = 0;
    const reasons: string[] = [];
    const t = RISK.thresholds;
    const p = RISK.points;

    // Access tokens outlive logout and refresh-token revocation by up to ACCESS_TOKEN_TTL. No live session means
    // the sign-in was revoked (logout, password reset, refresh-token reuse), so the leftover token is suspect.
    if (!user.refreshTokens?.some((s) => s.expiresAt.getTime() > now)) {
      score += p.noActiveSession;
      reasons.push(REASON.NO_ACTIVE_SESSION);
    }
    if (failedLogins >= t.failedMany) {
      score += p.failedMany;
      reasons.push(`${REASON.FAILED_LOGINS}:${failedLogins}`);
    } else if (failedLogins >= t.failedRepeated) {
      score += p.failedRepeated;
      reasons.push(`${REASON.FAILED_LOGINS}:${failedLogins}`);
    }
    if (downloads >= t.volumeExtreme) {
      score += p.volumeExtreme;
      reasons.push(`${REASON.DOWNLOAD_VOLUME}:${downloads}/h`);
    } else if (downloads >= t.volumeHigh) {
      score += p.volumeHigh;
      reasons.push(`${REASON.DOWNLOAD_VOLUME}:${downloads}/h`);
    }
    score = Math.min(100, score);
    return { score, level: levelOf(score), reasons };
  },
};
