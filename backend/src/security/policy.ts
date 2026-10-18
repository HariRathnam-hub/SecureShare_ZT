import type { AccessSignals, DeviceAssessment, PolicyDecision, RiskAssessment, TrustPolicy, TrustVerdict } from './types';

/**
 * Adaptive policy tuning. Every number here is a heuristic, not a security guarantee: a user-agent string
 * and an IP address are easy to change, so "new device" only ever nudges the score and can never deny on its own.
 */
export const RISK = {
  windows: { failedLoginsMs: 6 * 3_600_000, downloadsMs: 3_600_000 },
  /** Counts at or above which a signal fires. */
  thresholds: { failedRepeated: 3, failedMany: 5, volumeHigh: 15, volumeExtreme: 30 },
  points: { newDevice: 20, failedRepeated: 20, failedMany: 40, volumeHigh: 25, volumeExtreme: 45, noActiveSession: 50 },
  /** Score at which the level becomes medium / high. */
  levels: { medium: 30, high: 60 },
} as const;

export const REASON = {
  NO_ACTIVE_SESSION: 'no_active_session',
  FAILED_LOGINS: 'failed_logins',
  DOWNLOAD_VOLUME: 'download_volume',
  NEW_DEVICE: 'new_device',
} as const;

export const levelOf = (score: number): RiskAssessment['level'] =>
  score >= RISK.levels.high ? 'high' : score >= RISK.levels.medium ? 'medium' : 'low';

const verdict = (decision: PolicyDecision, reason: string): TrustVerdict => ({ decision, reason });

/**
 * Decision table (sensitive = confidential | restricted):
 *
 *  signed-out / revoked session           DENY (always)
 *  low risk                               ALLOW
 *  medium risk, public/internal           ALLOW (logged)
 *  medium risk, sensitive                 REQUIRE_APPROVAL
 *  high risk,   public/internal           REQUIRE_APPROVAL
 *  high risk,   sensitive                 DENY
 *
 * REQUIRE_APPROVAL is satisfied by an unexpired grant that came from an approved access request (the owner's
 * explicit, time-boxed decision), and is not applied to the owner, who has nobody to ask.
 * This runs after, and never replaces, the classification / grant / time-lock rules in access-policy.service.
 */
export const adaptivePolicy: TrustPolicy = {
  decide(signals: AccessSignals, risk: RiskAssessment, device: DeviceAssessment): TrustVerdict {
    const score = Math.min(100, risk.score + (device.trusted ? 0 : RISK.points.newDevice));
    const level = levelOf(score);
    const factors = [...risk.reasons, ...(device.trusted ? [] : [REASON.NEW_DEVICE, ...device.reasons])];
    const summary = `score=${score} level=${level}${factors.length ? ` factors=${factors.join(',')}` : ''}`;
    const sensitive = signals.resource.classification === 'confidential' || signals.resource.classification === 'restricted';

    if (risk.reasons.includes(REASON.NO_ACTIVE_SESSION)) {
      return verdict('DENY', `session is no longer active (signed out or revoked); ${summary}`);
    }
    if (level === 'low') return verdict('ALLOW', summary);
    if (level === 'high' && sensitive) return verdict('DENY', `high risk on a ${signals.resource.classification} file; ${summary}`);
    if (level === 'medium' && !sensitive) return verdict('ALLOW', `medium risk, non-sensitive file; ${summary}`);

    // Remaining cases need an approver.
    if (signals.isOwner) return verdict('ALLOW', `elevated risk, owner cannot self-approve; ${summary}`);
    if (signals.hasApprovedGrant) return verdict('ALLOW', `elevated risk, approved access request on file; ${summary}`);
    return verdict('REQUIRE_APPROVAL', `elevated risk requires owner approval; ${summary}`);
  },
};
