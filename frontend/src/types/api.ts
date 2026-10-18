export type Classification = 'public' | 'internal' | 'confidential' | 'restricted';
export interface Person { id: string; name: string; email: string }

export interface FileDTO {
  id: string;
  fileName: string;
  originalName: string;
  mimeType: string;
  size: number;
  sha256: string;
  currentVersion: number;
  classification: Classification;
  availableFrom: string | null;
  availableUntil: string | null;
  dataRoom: string | null;
  owner: Person | string;
  createdAt: string;
  updatedAt: string;
  access?: { isOwner: boolean; canDownload: boolean; requiresPurpose: boolean; reason: string | null };
  sharedWith?: { user: Person | string; permission: 'view' | 'download'; grantedAt: string; expiresAt: string | null }[];
}
export interface VersionDTO {
  versionNumber: number; size: number; mimeType: string; sha256: string; originalName: string;
  createdAt: string; uploadedBy: { id: string; name: string };
}
export interface LinkDTO {
  id: string;
  file: { id: string; fileName?: string; classification?: Classification };
  expiresAt: string; maxDownloads: number | null; currentDownloads: number; hasPassword: boolean;
  status: 'active' | 'expired' | 'revoked' | 'exhausted'; createdAt: string;
}
export interface AccessRequestDTO {
  id: string;
  file: { id: string; fileName?: string; classification?: Classification };
  requester: Person | { id: string };
  purpose: string; reason: string; status: 'pending' | 'approved' | 'rejected';
  reviewedAt: string | null; decisionNote: string | null; expiresAt: string | null; createdAt: string;
}
export type RoomRole = 'viewer' | 'editor' | 'manager';
export interface RoomDTO {
  id: string; name: string; description: string; myRole: RoomRole; memberCount: number; fileCount: number; createdAt: string;
  permissions: { viewerCanDownload: boolean; maxClassification: 'public' | 'internal' | 'confidential' };
  owner?: Person; members?: { user: Person; role: RoomRole; addedAt: string }[]; files?: FileDTO[];
}
export interface AuditItem {
  id: string; actor: Person | null; action: string; targetType: string; targetId: string;
  ip?: string; metadata: Record<string, unknown>; timestamp: string;
}
export const PURPOSES = ['project', 'research', 'audit', 'compliance', 'education', 'other'] as const;

// ---- Phase 3: security dashboard (admin) ----
export type PolicyDecision = 'ALLOW' | 'REQUIRE_APPROVAL' | 'DENY';
export interface SecurityRow {
  id: string; action: string; timestamp: string; detail: string; ip: string | null;
  actor: { name: string; email: string } | null;
  file: { id: string; name: string; classification: Classification } | null;
}
export interface SecurityOverview {
  windowHours: number;
  generatedAt: string;
  cloudflare: {
    accessEnabled: boolean; accessConfigured: boolean; teamDomain: string | null;
    verifiedSinceStart: number; rejectedSinceStart: number; lastRejectedAt: string | null; lastRejectReason: string | null;
  };
  tunnel: { status: 'manually_configured' | 'not_configured'; publicUrl: string | null; allowedOrigins: string[] };
  stats: {
    decisions: Record<PolicyDecision, number>;
    failedLogins: number; downloads: number; accessRequests: number; accessDenied: number;
  };
  recent: { securityEvents: SecurityRow[]; policyDecisions: SecurityRow[]; failedLogins: SecurityRow[]; downloads: SecurityRow[]; accessRequests: SecurityRow[] };
}
