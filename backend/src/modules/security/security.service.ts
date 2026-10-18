import { env } from '../../config/env';
import { accessStats } from '../../middleware/cloudflareAccess';
import { AuditAction, AuditLog } from '../audit/audit-log.model';
import { File } from '../files/file.model';

const LIMIT = 10;
const NON_ALLOW = { action: 'POLICY_DECISION', 'metadata.decision': { $ne: 'ALLOW' } } as const;

/** Short, safe, human-readable detail for the dashboard (never raw metadata). */
function detailOf(a: { action: AuditAction; metadata: Record<string, any> }): string {
  const m = a.metadata ?? {};
  switch (a.action) {
    case 'LOGIN_FAILED': return `${m.reason ?? 'failed'}${m.knownAccount === false ? ' (unknown account)' : ''}`;
    case 'LOGIN_SUCCESS': return m.newDevice ? 'sign-in from a user agent not seen before' : 'sign-in';
    case 'SESSION_REVOKED': return String(m.reason ?? 'revoked');
    case 'ACCESS_DENIED': return String(m.reason ?? m.need ?? 'denied');
    case 'POLICY_DECISION': return `${m.decision}: ${m.reason ?? ''}`;
    default: return '';
  }
}

export const securityService = {
  async overview(hours: number) {
    const since = new Date(Date.now() - hours * 3_600_000);
    const inWindow = { timestamp: { $gte: since } };
    const recent = (filter: Record<string, unknown>) =>
      AuditLog.find(filter).sort({ timestamp: -1 }).limit(LIMIT).populate('actor', 'name email').lean();

    const [decisionRows, failedLogins, downloads, accessRequests, denied, events, decisions, failed, dl, requests] = await Promise.all([
      AuditLog.aggregate<{ _id: string; n: number }>([
        { $match: { action: 'POLICY_DECISION', ...inWindow } },
        { $group: { _id: '$metadata.decision', n: { $sum: 1 } } },
      ]),
      AuditLog.countDocuments({ action: 'LOGIN_FAILED', ...inWindow }),
      AuditLog.countDocuments({ action: 'DOWNLOAD_FILE', ...inWindow }),
      AuditLog.countDocuments({ action: 'ACCESS_REQUEST', ...inWindow }),
      AuditLog.countDocuments({ action: 'ACCESS_DENIED', ...inWindow }),
      recent({
        $or: [
          { action: { $in: ['LOGIN_FAILED', 'ACCESS_DENIED', 'SESSION_REVOKED'] } },
          NON_ALLOW,
          { action: 'LOGIN_SUCCESS', 'metadata.newDevice': true },
        ],
      }),
      recent({ action: 'POLICY_DECISION' }),
      recent({ action: 'LOGIN_FAILED' }),
      recent({ action: 'DOWNLOAD_FILE' }),
      recent({ action: { $in: ['ACCESS_REQUEST', 'APPROVE_ACCESS', 'REJECT_ACCESS'] } }),
    ]);

    // Resolve file names for the lists that point at files (deleted files simply have no name).
    const fileIds = [...dl, ...requests, ...decisions].filter((a) => a.targetType === 'file').map((a) => a.targetId);
    const requestFileIds = requests.map((a) => (a.metadata as any)?.fileId).filter(Boolean);
    const files = await File.find({ _id: { $in: [...fileIds, ...requestFileIds] } }).select('fileName classification').lean();
    const fileById = new Map(files.map((f) => [String(f._id), f]));
    const fileOf = (a: any) => {
      const id = a.targetType === 'file' ? String(a.targetId) : a.metadata?.fileId;
      const f = id ? fileById.get(String(id)) : undefined;
      return f ? { id: String(f._id), name: f.fileName, classification: f.classification } : null;
    };

    const row = (a: any) => ({
      id: String(a._id),
      action: a.action as AuditAction,
      timestamp: a.timestamp as Date,
      actor: a.actor ? { name: a.actor.name as string, email: a.actor.email as string } : null,
      ip: (a.ip as string | undefined) ?? null,
      detail: detailOf(a),
      file: fileOf(a),
    });

    const count = (k: string) => decisionRows.find((r) => r._id === k)?.n ?? 0;
    return {
      windowHours: hours,
      generatedAt: new Date(),
      cloudflare: {
        accessEnabled: env.cloudflareAccess.enabled,
        accessConfigured: env.cloudflareAccess.configured,
        teamDomain: env.cloudflareAccess.teamDomain ?? null,
        // Counters since this server process started. Zero verified requests means "not yet seen working", not "broken".
        verifiedSinceStart: accessStats.verified,
        rejectedSinceStart: accessStats.rejected,
        lastRejectedAt: accessStats.lastRejectedAt,
        lastRejectReason: accessStats.lastRejectReason,
      },
      tunnel: {
        // Declared by the operator through TUNNEL_PUBLIC_URL. The server cannot verify that a tunnel is running.
        status: env.TUNNEL_PUBLIC_URL ? ('manually_configured' as const) : ('not_configured' as const),
        publicUrl: env.TUNNEL_PUBLIC_URL ?? null,
        allowedOrigins: env.allowedOrigins,
      },
      stats: {
        decisions: { ALLOW: count('ALLOW'), REQUIRE_APPROVAL: count('REQUIRE_APPROVAL'), DENY: count('DENY') },
        failedLogins, downloads, accessRequests, accessDenied: denied,
      },
      recent: {
        securityEvents: events.map(row),
        policyDecisions: decisions.map(row),
        failedLogins: failed.map(row),
        downloads: dl.map(row),
        accessRequests: requests.map(row),
      },
    };
  },
};
