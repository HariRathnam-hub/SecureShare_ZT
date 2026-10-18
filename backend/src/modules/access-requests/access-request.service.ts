import { AppError } from '../../utils/AppError';
import { Actor, auditService } from '../audit/audit.service';
import { evaluateFileAccess, RESTRICTED_MAX_GRANT_DAYS } from '../files/access-policy.service';
import { previewTrust } from '../files/download-policy.service';
import { File } from '../files/file.model';
import { upsertGrant } from '../files/file.service';
import { AccessRequest } from './access-request.model';

const dto = (r: any) => ({
  id: String(r._id),
  file: r.fileId?.fileName ? { id: String(r.fileId._id), fileName: r.fileId.fileName, classification: r.fileId.classification } : { id: String(r.fileId) },
  requester: r.requester?.name ? { id: String(r.requester._id), name: r.requester.name, email: r.requester.email } : { id: String(r.requester) },
  purpose: r.purpose,
  reason: r.reason,
  status: r.status,
  reviewedAt: r.reviewedAt ?? null,
  decisionNote: r.decisionNote ?? null,
  expiresAt: r.expiresAt ?? null,
  createdAt: r.createdAt,
});

export const accessRequestService = {
  async create(actor: Actor, fileId: string, input: { purpose: any; reason: string }) {
    const file = await File.findById(fileId);
    if (!file) throw new AppError('File not found', 404);
    const access = await evaluateFileAccess(file, actor.id);
    if (access.isOwner) throw new AppError('You own this file', 400);
    if (access.canDownload) {
      // Nothing to request, unless the adaptive policy currently demands owner approval for this user.
      const trust = await previewTrust(actor, file, access);
      if (trust.verdict.decision !== 'REQUIRE_APPROVAL') throw new AppError('You already have access to this file', 409);
    }
    try {
      const req = await AccessRequest.create({
        fileId: file._id, fileOwner: file.owner, requester: actor.id, purpose: input.purpose, reason: input.reason,
      });
      await auditService.record(actor, 'ACCESS_REQUEST', 'accessRequest', req.id, {
        fileId: file.id, purpose: input.purpose, reason: input.reason, classification: file.classification,
        roomId: file.dataRoom ? String(file.dataRoom) : undefined,
      });
      return dto(req.toObject());
    } catch (err: any) {
      if (err?.code === 11000) throw new AppError('You already have a pending request for this file', 409);
      throw err;
    }
  },

  async list(actor: Actor, q: { box: 'incoming' | 'outgoing'; status?: string }) {
    const filter: Record<string, unknown> = q.box === 'incoming' ? { fileOwner: actor.id } : { requester: actor.id };
    if (q.status) filter.status = q.status;
    const items = await AccessRequest.find(filter).sort({ createdAt: -1 }).limit(200)
      .populate('fileId', 'fileName classification').populate('requester', 'name email').lean();
    return items.map(dto);
  },

  async approve(actor: Actor, id: string, input: { expiresInDays: number; permission: 'view' | 'download'; note?: string }) {
    // Pre-check (read-only) so restricted-file limits are enforced before any state changes.
    const existing = await AccessRequest.findOne({ _id: id, fileOwner: actor.id, status: 'pending' });
    if (!existing) throw new AppError('Request not found or already reviewed', 404);
    const file = await File.findById(existing.fileId);
    if (!file) throw new AppError('This file no longer exists', 409);

    const restricted = file.classification === 'restricted';
    if (restricted && input.expiresInDays > RESTRICTED_MAX_GRANT_DAYS) {
      throw new AppError(`Access to restricted files can be granted for at most ${RESTRICTED_MAX_GRANT_DAYS} days`, 400);
    }
    const permission = restricted ? 'download' : input.permission; // restricted grants are always download + purpose
    const expiresAt = new Date(Date.now() + input.expiresInDays * 86_400_000);

    // Atomic pending -> approved, scoped to the file owner (ownership verified in the query itself).
    const req = await AccessRequest.findOneAndUpdate(
      { _id: id, fileOwner: actor.id, status: 'pending' },
      { status: 'approved', reviewedBy: actor.id, reviewedAt: new Date(), decisionNote: input.note, expiresAt },
      { new: true },
    );
    if (!req) throw new AppError('Request not found or already reviewed', 404);
    await upsertGrant(file._id, { user: String(req.requester), permission, grantedBy: actor.id, expiresAt, requestId: req.id });
    await auditService.record(actor, 'APPROVE_ACCESS', 'accessRequest', req.id, {
      fileId: file.id, requester: String(req.requester), permission, expiresAt, purpose: req.purpose, reason: req.reason,
      classification: file.classification, roomId: file.dataRoom ? String(file.dataRoom) : undefined,
    });
    return dto(req.toObject());
  },

  async reject(actor: Actor, id: string, input: { note?: string }) {
    const req = await AccessRequest.findOneAndUpdate(
      { _id: id, fileOwner: actor.id, status: 'pending' },
      { status: 'rejected', reviewedBy: actor.id, reviewedAt: new Date(), decisionNote: input.note },
      { new: true },
    );
    if (!req) throw new AppError('Request not found or already reviewed', 404);
    await auditService.record(actor, 'REJECT_ACCESS', 'accessRequest', req.id, { fileId: String(req.fileId), requester: String(req.requester) });
    return dto(req.toObject());
  },
};
