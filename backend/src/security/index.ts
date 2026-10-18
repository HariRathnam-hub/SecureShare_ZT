import { env } from '../config/env';
import { logger } from '../utils/logger';
import { CloudflareAccessVerifier } from './cloudflare-access';
import { adaptivePolicy } from './policy';
import { dbRiskEngine, userAgentDeviceTrust } from './signals';
import type {
  AccessSignals, DeviceAssessment, EdgeIdentityVerifier, RiskAssessment, TrustVerdict,
} from './types';

export * from './types';

const noEdge: EdgeIdentityVerifier = {
  async verify() {
    return null;
  },
};

const { enabled, teamDomain, aud } = env.cloudflareAccess;

/** Active providers. Swap any of them with configureSecurity(). */
export const security = {
  risk: dbRiskEngine,
  device: userAgentDeviceTrust,
  policy: adaptivePolicy,
  // Only ever verifies real Cloudflare assertions; stays a no-op until Access is explicitly enabled and configured.
  edge: (enabled && teamDomain && aud ? new CloudflareAccessVerifier({ teamDomain, audience: aud }) : noEdge) as EdgeIdentityVerifier,
};

export function configureSecurity(overrides: Partial<typeof security>): void {
  Object.assign(security, overrides);
}

export interface TrustEvaluation {
  verdict: TrustVerdict;
  risk: RiskAssessment;
  device: DeviceAssessment;
}

/**
 * Called on every download (and when previewing whether approval is needed). Never throws:
 * if the checks themselves fail, restricted files fail CLOSED and everything else fails open (and is logged).
 */
export async function evaluateTrust(signals: AccessSignals): Promise<TrustEvaluation> {
  try {
    const [risk, device] = await Promise.all([security.risk.assess(signals), security.device.assess(signals)]);
    return { verdict: security.policy.decide(signals, risk, device), risk, device };
  } catch (err) {
    logger.error('Trust evaluation failed', { message: (err as Error).message, fileId: signals.resource.id });
    const closed = signals.resource.classification === 'restricted';
    return {
      verdict: closed
        ? { decision: 'DENY', reason: 'policy checks failed; restricted files fail closed' }
        : { decision: 'ALLOW', reason: 'risk checks unavailable; non-restricted file allowed' },
      risk: { score: 0, level: 'low', reasons: ['evaluation_failed'] },
      device: { trusted: false, reasons: ['evaluation_failed'] },
    };
  }
}
