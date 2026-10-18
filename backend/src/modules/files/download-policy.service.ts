import { evaluateTrust, TrustEvaluation } from '../../security';
import type { AccessSignals } from '../../security/types';
import { AppError } from '../../utils/AppError';
import { Actor, auditService } from '../audit/audit.service';
import { User } from '../user/user.model';
import { AccessDecision, evaluateFileAccess, evaluateLinkAccess, hasApprovedGrant } from './access-policy.service';
import { File, FileDocument } from './file.model';
import type { PurposeContext } from './delivery.service';

type Via = 'direct' | 'link';

export const APPROVAL_REQUIRED = 'APPROVAL_REQUIRED';

function signalsFor(actor: Actor, file: FileDocument, access: AccessDecision, via: Via): AccessSignals {
  return {
    userId: actor.id, email: actor.email, role: actor.role, ip: actor.ip, userAgent: actor.userAgent,
    action: 'download', via, device: actor.device, edge: actor.edge,
    isOwner: access.isOwner, hasApprovedGrant: hasApprovedGrant(file, actor.id),
    resource: { type: 'file', id: file.id, classification: file.classification, roomId: file.dataRoom ? String(file.dataRoom) : undefined },
  };
}

/** Read-only look at the adaptive decision (no audit write). Lets access requests ask "does this user need approval right now?". */
export const previewTrust = (actor: Actor, file: FileDocument, access: AccessDecision, via: Via = 'direct'): Promise<TrustEvaluation> =>
  evaluateTrust(signalsFor(actor, file, access, via));

/**
 * The last gate before bytes are read, for direct downloads AND link redemptions. Everything is re-derived from
 * current server state, so a ban, revoked share, lapsed grant, reclassification or closed time window that happened
 * after the caller's own checks still stops the download:
 *
 *   1. user still exists and is active
 *   2. file still exists; ownership, classification, grants, room membership, time window and link rules are
 *      re-evaluated by the existing access-policy functions (no parallel rule set)
 *   3. purpose + reason still required for confidential/restricted non-owner downloads
 *   4. adaptive risk decision: ALLOW | REQUIRE_APPROVAL | DENY
 *
 * Every outcome is written to the audit log (POLICY_DECISION) before this returns or throws.
 */
export async function authorizeDownload(p: {
  actor: Actor; file: FileDocument; via: Via; linkId?: string; context: PurposeContext;
}): Promise<{ file: FileDocument; access: AccessDecision; trust: TrustEvaluation }> {
  const { actor, via } = p;
  const base = { via, linkId: p.linkId, classification: p.file.classification, roomId: p.file.dataRoom ? String(p.file.dataRoom) : undefined, edge: actor.edge?.email };

  const deny = async (reason: string, message: string, status = 403): Promise<never> => {
    await auditService.record(actor, 'POLICY_DECISION', 'file', p.file.id, { ...base, decision: 'DENY', reason, stage: 'recheck' });
    throw new AppError(message, status);
  };

  const user = await User.findById(actor.id).select('isActive');
  if (!user || !user.isActive) return deny('user_inactive', 'This account has been disabled');

  const file = await File.findById(p.file._id);
  if (!file) return deny('file_removed', 'File not found', 404);

  const access = via === 'link' ? evaluateLinkAccess(file, actor.id) : await evaluateFileAccess(file, actor.id);
  if (!access.canDownload) return deny(`access_revoked: ${access.denyReason ?? 'no download right'}`, access.denyReason ?? 'Download not permitted');

  if (access.requiresPurpose && !(p.context.purpose && p.context.reason)) {
    throw new AppError('A purpose and reason are required to access confidential files', 428);
  }

  const trust = await evaluateTrust(signalsFor(actor, file, access, via));
  const { decision, reason } = trust.verdict;
  await auditService.record(actor, 'POLICY_DECISION', 'file', file.id, {
    ...base, decision, reason, stage: 'adaptive', access: access.via,
    risk: trust.risk, device: trust.device,
  });

  if (decision === 'REQUIRE_APPROVAL') {
    throw new AppError('Elevated risk detected: the file owner must approve your access first. Send an access request for this file, then try again.', 403, true, APPROVAL_REQUIRED);
  }
  if (decision === 'DENY') throw new AppError('Access denied by security policy', 403);
  return { file, access, trust };
}
