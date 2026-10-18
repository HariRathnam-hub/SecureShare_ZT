import { createHash, randomUUID } from 'crypto';
import path from 'path';
import { Types } from 'mongoose';
import { AppError } from '../../utils/AppError';
import { logger } from '../../utils/logger';
import { deleteMany, getStorage } from '../../storage';
import { Actor, SYSTEM_TARGET_ID, auditService } from '../audit/audit.service';
import { SharedLink } from '../links/shared-link.model';
import { DataRoom, roomRole } from '../rooms/data-room.model';
import { User } from '../user/user.model';
import { evaluateFileAccess } from './access-policy.service';
import { deliverFile, PurposeContext } from './delivery.service';
import { toFileDTO } from './file.dto';
import { CLASS_RANK, Classification, File, FileDocument, SharePermission } from './file.model';
import { FileVersion } from './file-version.model';
import { inspectUpload, safeName } from './upload';

const NOT_FOUND = () => new AppError('File not found', 404);
const sha256 = (b: Buffer) => createHash('sha256').update(b).digest('hex');
const escapeRegex = (s: string) => s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');

/** Load + authorise in one step. No view right => 404 (existence is not revealed). */
export async function loadAuthorised(actor: Actor, fileId: string, need: 'view' | 'download' | 'owner') {
  const file = await File.findById(fileId).select('+storageKey');
  if (!file) throw NOT_FOUND();
  const access = await evaluateFileAccess(file, actor.id);
  if (!access.canView) {
    await auditService.record(actor, 'ACCESS_DENIED', 'file', file.id, { need, reason: access.denyReason ?? 'no_grant' });
    throw NOT_FOUND();
  }
  if (need === 'owner' && !access.isOwner) {
    await auditService.record(actor, 'ACCESS_DENIED', 'file', file.id, { need, reason: 'not_owner' });
    throw new AppError('Only the file owner can do this', 403);
  }
  if (need === 'download' && !access.canDownload) {
    await auditService.record(actor, 'ACCESS_DENIED', 'file', file.id, { need, reason: access.denyReason });
    throw new AppError(access.denyReason ?? 'Download not permitted', 403);
  }
  return { file, access };
}

/** Insert or replace a user's grant atomically. Shared with the access-request flow. */
export async function upsertGrant(
  fileId: Types.ObjectId | string,
  grant: { user: string; permission: SharePermission; grantedBy: string; expiresAt?: Date; requestId?: string },
) {
  await File.updateOne({ _id: fileId }, { $pull: { sharedWith: { user: grant.user } } });
  await File.updateOne({ _id: fileId }, { $push: { sharedWith: { ...grant, grantedAt: new Date() } } });
}

/** inspectUpload + an audit row for every rejected upload (type, extension or signature mismatch). Never records file content. */
async function inspectAudited(actor: Actor, raw: Express.Multer.File | undefined, fileId?: Types.ObjectId | string) {
  try {
    return inspectUpload(raw);
  } catch (err) {
    if (err instanceof AppError) {
      await auditService
        .record(actor, 'UPLOAD_REJECTED', fileId ? 'file' : 'system', fileId ?? SYSTEM_TARGET_ID, {
          reason: err.message, status: err.statusCode,
          name: raw ? safeName(raw.originalname) : undefined, claimedType: raw?.mimetype?.slice(0, 100), size: raw?.size,
        })
        .catch((e) => logger.error('Upload-rejection audit write failed', { err: e }));
    }
    throw err;
  }
}

const extOf = (n: string) => path.extname(n).toLowerCase();
const withExt = (name: string, original: string) => (extOf(name) === extOf(original) ? name : `${name}${extOf(original)}`);

export const fileService = {
  async upload(actor: Actor, raw: Express.Multer.File | undefined, input: { classification: Classification; roomId?: string; availableFrom?: Date; availableUntil?: Date },
  ) {
    const up = await inspectAudited(actor, raw);
    if (input.roomId) {
      const room = await DataRoom.findById(input.roomId).lean();
      const role = room ? roomRole(room, actor.id) : null;
      if (!room || !role) throw new AppError('Data room not found', 404);
      if (role === 'viewer') throw new AppError('Viewers cannot upload to this room', 403);
      if (CLASS_RANK[input.classification] > CLASS_RANK[room.permissions.maxClassification]) {
        throw new AppError(`This room does not accept ${input.classification} files`, 400);
      }
    }
    const _id = new Types.ObjectId();
    const storageKey = `files/${actor.id}/${_id}/v1/${randomUUID()}`;
    const hash = sha256(up.buffer);
    await getStorage().uploadFile(storageKey, up.buffer, { contentType: up.mimeType });
    try {
      const file = await File.create({
        _id, owner: actor.id, fileName: up.originalName, originalName: up.originalName, mimeType: up.mimeType,
        size: up.size, sha256: hash, storageKey, currentVersion: 1, classification: input.classification,
        dataRoom: input.roomId, availableFrom: input.availableFrom, availableUntil: input.availableUntil,
      });
      await FileVersion.create({
        fileId: _id, versionNumber: 1, storageKey, uploadedBy: actor.id, originalName: up.originalName,
        mimeType: up.mimeType, size: up.size, sha256: hash,
      });
      await auditService.record(actor, 'UPLOAD_FILE', 'file', _id, {
        name: up.originalName, size: up.size, mimeType: up.mimeType, classification: input.classification,
        sha256: hash, roomId: input.roomId, availableFrom: input.availableFrom, availableUntil: input.availableUntil,
      });
      return toFileDTO(file, await evaluateFileAccess(file, actor.id));
    } catch (err) {
      await Promise.allSettled([deleteMany(getStorage(), [storageKey]), File.deleteOne({ _id }), FileVersion.deleteMany({ fileId: _id })]);
      throw err;
    }
  },

  async addVersion(actor: Actor, fileId: string, raw: Express.Multer.File | undefined) {
    const { file } = await loadAuthorised(actor, fileId, 'owner');
    const up = await inspectAudited(actor, raw, file._id);
    const next = file.currentVersion + 1;
    const storageKey = `files/${actor.id}/${file.id}/v${next}/${randomUUID()}`;
    const hash = sha256(up.buffer);
    await getStorage().uploadFile(storageKey, up.buffer, { contentType: up.mimeType });
    try {
      await FileVersion.create({
        fileId: file._id, versionNumber: next, storageKey, uploadedBy: actor.id, originalName: up.originalName,
        mimeType: up.mimeType, size: up.size, sha256: hash,
      });
      // Optimistic concurrency: only advance if nobody else did meanwhile.
      const updated = await File.findOneAndUpdate(
        { _id: file._id, currentVersion: file.currentVersion },
        { storageKey, mimeType: up.mimeType, size: up.size, sha256: hash, currentVersion: next },
        { new: true },
      );
      if (!updated) throw new AppError('The file changed while uploading. Try again.', 409);
      await auditService.record(actor, 'UPLOAD_VERSION', 'file', file.id, {
        version: next, size: up.size, sha256: hash, roomId: file.dataRoom ? String(file.dataRoom) : undefined,
      });
      return toFileDTO(updated, await evaluateFileAccess(updated, actor.id));
    } catch (err) {
      await Promise.allSettled([deleteMany(getStorage(), [storageKey]), FileVersion.deleteOne({ fileId: file._id, versionNumber: next, storageKey })]);
      throw err;
    }
  },

  async list(actor: Actor, q: { scope: 'owned' | 'shared'; q?: string; page: number; limit: number }) {
    const now = new Date();
    const filter: Record<string, unknown> = {};
    if (q.scope === 'owned') {
      filter.owner = actor.id;
    } else {
      const roomIds = await DataRoom.find({ $or: [{ owner: actor.id }, { 'members.user': actor.id }] }).distinct('_id');
      filter.owner = { $ne: actor.id };
      const live = [{ expiresAt: { $exists: false } }, { expiresAt: null }, { expiresAt: { $gt: now } }];
      filter.$or = [
        // Non-restricted: any unexpired direct grant.
        { classification: { $ne: 'restricted' }, sharedWith: { $elemMatch: { user: actor.id, $or: live } } },
        // Restricted: only time-boxed grants that came from an approved access request.
        { classification: 'restricted', sharedWith: { $elemMatch: { user: actor.id, requestId: { $exists: true }, expiresAt: { $gt: now } } } },
        // Room membership never exposes restricted files.
        { classification: { $ne: 'restricted' }, dataRoom: { $in: roomIds } },
      ];
    }
    if (q.q) filter.fileName = { $regex: escapeRegex(q.q), $options: 'i' };
    const [files, total] = await Promise.all([
      File.find(filter).sort({ updatedAt: -1 }).skip((q.page - 1) * q.limit).limit(q.limit).populate('owner', 'name email'),
      File.countDocuments(filter),
    ]);
    return { total, page: q.page, limit: q.limit, files: files.map((f) => toFileDTO(f)) };
  },

  async get(actor: Actor, fileId: string) {
    const { file, access } = await loadAuthorised(actor, fileId, 'view');
    await file.populate([{ path: 'owner', select: 'name email' }, { path: 'sharedWith.user', select: 'name email' }]);
    const versions = await FileVersion.find({ fileId: file._id }).sort({ versionNumber: -1 }).populate('uploadedBy', 'name email').lean();
    return {
      file: toFileDTO(file, access, { includeShares: access.isOwner }),
      versions: versions.map((v: any) => ({
        versionNumber: v.versionNumber, size: v.size, mimeType: v.mimeType, sha256: v.sha256,
        originalName: v.originalName, createdAt: v.createdAt,
        uploadedBy: { id: String(v.uploadedBy._id), name: v.uploadedBy.name },
      })),
    };
  },

  async update(
    actor: Actor,
    fileId: string,
    patch: {
      fileName?: string;
      classification?: Classification;
      availableFrom?: Date | null;
      availableUntil?: Date | null;
    },
  ) {
    const { file } = await loadAuthorised(actor, fileId, 'owner');
    const lock = (f: { availableFrom?: Date; availableUntil?: Date }) => ({
      availableFrom: f.availableFrom ?? null,
      availableUntil: f.availableUntil ?? null,
    });
    const before = { fileName: file.fileName, classification: file.classification, ...lock(file) };
    const raised = patch.classification && CLASS_RANK[patch.classification] > CLASS_RANK[file.classification];

    const nextFrom = patch.availableFrom !== undefined ? patch.availableFrom ?? undefined : file.availableFrom;
    const nextUntil = patch.availableUntil !== undefined ? patch.availableUntil ?? undefined : file.availableUntil;
    if (nextFrom && nextUntil && nextUntil <= nextFrom) {
      throw new AppError('availableUntil must be after availableFrom', 400);
    }

    if (patch.classification && file.dataRoom) {
      const room = await DataRoom.findById(file.dataRoom).lean();
      if (room && CLASS_RANK[patch.classification] > CLASS_RANK[room.permissions.maxClassification]) {
        throw new AppError('Remove the file from its data room before raising its classification', 409);
      }
    }
    if (patch.fileName) file.fileName = withExt(patch.fileName, file.originalName);
    if (patch.classification) file.classification = patch.classification;
    file.availableFrom = nextFrom;
    file.availableUntil = nextUntil;
    if (patch.classification === 'restricted') {
      // Restricted honours only approved-request grants; drop direct shares now.
      const kept = file.sharedWith.filter((g) => g.requestId && g.expiresAt).map((g) => (g as any).toObject?.() ?? g);
      file.set('sharedWith', kept);
    }
    await file.save();

    // Raising classification invalidates previously issued links (assume breach).
    if (raised) await SharedLink.updateMany({ fileId: file._id, isActive: true }, { isActive: false });

    await auditService.record(actor, 'UPDATE_FILE', 'file', file.id, {
      before,
      after: { fileName: file.fileName, classification: file.classification, ...lock(file) },
      linksRevoked: !!raised,
      roomId: file.dataRoom ? String(file.dataRoom) : undefined,
    });
    return toFileDTO(file, await evaluateFileAccess(file, actor.id), { includeShares: true });
  },

  async remove(actor: Actor, fileId: string) {
    const { file } = await loadAuthorised(actor, fileId, 'owner');
    const versions = await FileVersion.find({ fileId: file._id }).select('+storageKey');
    // Audit first (with a snapshot), then destroy.
    await auditService.record(actor, 'DELETE_FILE', 'file', file.id, {
      name: file.fileName, classification: file.classification, versions: versions.length, sha256: file.sha256,
      roomId: file.dataRoom ? String(file.dataRoom) : undefined,
    });
    await deleteMany(getStorage(), versions.map((v) => v.storageKey).concat(file.storageKey));
    await Promise.all([
      FileVersion.deleteMany({ fileId: file._id }),
      SharedLink.updateMany({ fileId: file._id }, { isActive: false }),
      File.deleteOne({ _id: file._id }),
    ]);
  },

  async download(actor: Actor, fileId: string, input: PurposeContext & { version?: number }) {
    const { file, access } = await loadAuthorised(actor, fileId, 'download');
    if (access.requiresPurpose && !(input.purpose && input.reason)) {
      throw new AppError('A purpose and reason are required to access confidential files', 428);
    }
    return deliverFile({
      actor, file, access, via: 'direct', versionNumber: input.version,
      context: { purpose: input.purpose, reason: input.reason },
    });
  },

  async shareWithUser(actor: Actor, fileId: string, input: { email: string; permission: SharePermission; expiresAt?: Date }) {
    const { file } = await loadAuthorised(actor, fileId, 'owner');
    if (file.classification === 'restricted') {
      throw new AppError('Restricted files are shared only through approved access requests', 400);
    }
    if (input.expiresAt && input.expiresAt <= new Date()) throw new AppError('Expiry must be in the future', 400);
    const target = await User.findOne({ email: input.email, isActive: true, isEmailVerified: true });
    if (!target) throw new AppError('No active user with that email', 404);
    if (target.id === actor.id) throw new AppError('You already own this file', 400);
    await upsertGrant(file._id, { user: target.id, permission: input.permission, grantedBy: actor.id, expiresAt: input.expiresAt });
    await auditService.record(actor, 'SHARE_FILE_USER', 'file', file.id, {
      sharedWith: target.id, email: target.email, permission: input.permission, expiresAt: input.expiresAt,
      roomId: file.dataRoom ? String(file.dataRoom) : undefined,
    });
  },

  async revokeShare(actor: Actor, fileId: string, userId: string) {
    const { file } = await loadAuthorised(actor, fileId, 'owner');
    await File.updateOne({ _id: file._id }, { $pull: { sharedWith: { user: userId } } });
    await auditService.record(actor, 'REVOKE_FILE_SHARE', 'file', file.id, { revokedFrom: userId });
  },
};

logger.debug('file.service loaded');
