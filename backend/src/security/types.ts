/**
 * Zero Trust provider interfaces. Each provider can be swapped with configureSecurity()
 * without touching file, link, room or audit code. Defaults live in ./index.ts.
 */
import type { Classification } from '../modules/files/file.model';
import type { Role } from '../modules/user/user.model';

/** Identity asserted by an edge proxy (e.g. a verified Cloudflare Access JWT). */
export interface EdgeIdentity {
  provider: 'cloudflare-access' | string;
  email?: string;
  subject?: string;
  claims?: Record<string, unknown>;
}

/** Device facts attached to a request once device registration exists. */
export interface DeviceContext {
  deviceId?: string;
  fingerprint?: string;
  trusted?: boolean;
}

/** Everything a trust decision may look at. Extend, never break. */
export interface AccessSignals {
  userId: string;
  email: string;
  role: Role;
  ip?: string;
  userAgent?: string;
  action: 'view' | 'download';
  via: 'direct' | 'link';
  resource: { type: 'file'; id: string; classification: Classification; roomId?: string };
  /** Filled by the download policy from fresh server state, never from client input. */
  isOwner?: boolean;
  /** True when an unexpired grant created by an APPROVED access request exists for this user. */
  hasApprovedGrant?: boolean;
  device?: DeviceContext;
  edge?: EdgeIdentity;
}

export interface RiskAssessment {
  /** 0 (no risk) to 100 (maximum risk). */
  score: number;
  level: 'low' | 'medium' | 'high';
  reasons: string[];
}

export interface DeviceAssessment {
  trusted: boolean;
  deviceId?: string;
  reasons: string[];
}

export type PolicyDecision = 'ALLOW' | 'REQUIRE_APPROVAL' | 'DENY';

/** The single outcome of a trust evaluation. `reason` is stored in the audit log, never shown verbatim to the client. */
export interface TrustVerdict {
  decision: PolicyDecision;
  reason: string;
}

/** Computes a risk score from signals (anomalies, geo, velocity, ...). */
export interface RiskEngine {
  assess(signals: AccessSignals): Promise<RiskAssessment>;
}
/** Decides whether the calling device is registered and trusted. */
export interface DeviceTrustProvider {
  assess(signals: AccessSignals): Promise<DeviceAssessment>;
}
/**
 * Verifies identity asserted by an edge proxy (Cloudflare Access).
 * Resolves null when no assertion is present; REJECTS (EdgeVerificationError) when one is present but invalid.
 */
export interface EdgeIdentityVerifier {
  verify(headers: Record<string, string | string[] | undefined>): Promise<EdgeIdentity | null>;
}
/** Combines risk + device posture + classification into one enforceable verdict. */
export interface TrustPolicy {
  decide(signals: AccessSignals, risk: RiskAssessment, device: DeviceAssessment): TrustVerdict;
}
