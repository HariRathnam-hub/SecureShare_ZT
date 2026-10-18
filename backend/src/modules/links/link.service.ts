import bcrypt from 'bcrypt';
import { env } from '../../config/env';
import { AppError } from '../../utils/AppError';
import { randomToken, sha256 } from '../../utils/crypto';
import { Actor, auditService } from '../audit/audit.service';
import { evaluateLinkAccess } from '../files/access-policy.service';
import { deliverFile } from '../files/delivery.service';
import { loadAuthorised } from '../files/file.service';
import { toFileDTO } from '../files/file.dto';
import { File } from '../files/file.model';
import { ISharedLink, SharedLink } from './shared-link.model';

const MAX_PASSWORD_ATTEMPTS = 5;
// One generic message for unknown / expired / revoked / exhausted / restricted: no oracle.
const INVALID = () => new AppError('This link is invalid or has expired', 404);

const statusOf = (l: Pick<ISharedLink, 'isActive' | 'expiresAt' | 'maxDownloads' | 'currentDownloads'>) =>
  !l.isActive ? 'revoked'
  : l.expiresAt <= new Date() ? 'expired'
  : l.maxDownloads && l.currentDownloads >= l.maxDownloads ? 'exhausted'
  : 'active';

async function resolve(actor: Actor, token: string, password: string | undefined) {
  const link = await SharedLink.findOne({ tokenHash: sha256(token) }).select('+tokenHash +passwordHash');
  if (!link || statusOf(link) !== 'active') throw INVALID();
  const file = await File.findById(link.fileId).select('+storageKey');
  if (!file || file.classification === 'restricted') throw INVALID();

  if (link.passwordHash) {
    if (!password) throw new AppError('This link requires a password', 403);
    if (!(await bcrypt.compare(password, link.passwordHash))) {
      const updated = await SharedLink.findOneAndUpdate({ _id: link._id }, { $inc: { failedAttempts: 1 } }, { new: true });
      const locked = !!updated && updated.failedAttempts >= MAX_PASSWORD_ATTEMPTS;
      if (locked) await SharedLink.updateOne({ _id: link._id }, { isActive: false });
      await auditService.record(actor, 'ACCESS_DENIED', 'link', link.id, { reason: 'wrong_password', locked });
      throw new AppError(locked ? 'Too many wrong passwords. This link is now disabled.' : 'Incorrect password', 403);
    }
  }
  const access = evaluateLinkAccess(file, actor.id);
  if (!access.canDownload) {
    await auditService.record(actor, 'ACCESS_DENIED', 'link', link.id, { reason: access.denyReason, fileId: file.id });
    throw new AppError(access.denyReason ?? 'Access denied', 403);
  }
  return { link, file, access };
}

const toLinkDTO = (l: any) => ({
  id: String(l._id),
  file: l.fileId && l.fileId.fileName ? { id: String(l.fileId._id), fileName: l.fileId.fileName, classification: l.fileId.classification } : { id: String(l.fileId) },
  expiresAt: l.expiresAt,
  maxDownloads: l.maxDownloads ?? null,
  currentDownloads: l.currentDownloads,
  hasPassword: !!l.passwordHash,
  status: statusOf(l),
  createdAt: l.createdAt,
});

export const linkService = {
  async create(actor: Actor, fileId: string, input: { expiresInMinutes: number; maxDownloads?: number; password?: string }) {
    const { file } = await loadAuthorised(actor, fileId, 'owner');
    if (file.classification === 'restricted') throw new AppError('Restricted files cannot be shared by link', 400);
    if (file.classification === 'confidential') {
      if (!input.password) throw new AppError('Links to confidential files must be password-protected', 400);
      if (input.expiresInMinutes > 10_080) throw new AppError('Links to confidential files can last at most 7 days', 400);
    }
    const token = randomToken(32);
    const link = await SharedLink.create({
      fileId: file._id,
      createdBy: actor.id,
      tokenHash: sha256(token),
      passwordHash: input.password ? await bcrypt.hash(input.password, env.BCRYPT_ROUNDS) : undefined,
      expiresAt: new Date(Date.now() + input.expiresInMinutes * 60_000),
      maxDownloads: input.maxDownloads ?? null,
    });
    await auditService.record(actor, 'CREATE_SHARE_LINK', 'link', link.id, {
      fileId: file.id, expiresAt: link.expiresAt, maxDownloads: link.maxDownloads, oneTime: link.maxDownloads === 1,
      passwordProtected: !!input.password, roomId: file.dataRoom ? String(file.dataRoom) : undefined,
    });
    return { token, link: toLinkDTO(link.toObject()) };
  },

  async listMine(actor: Actor) {
    const links = await SharedLink.find({ createdBy: actor.id }).sort({ createdAt: -1 }).limit(200).select('+passwordHash').populate('fileId', 'fileName classification').lean();
    return links.map(toLinkDTO);
  },

  async revoke(actor: Actor, id: string) {
    const link = await SharedLink.findOneAndUpdate({ _id: id, createdBy: actor.id }, { isActive: false });
    if (!link) throw new AppError('Link not found', 404);
    await auditService.record(actor, 'REVOKE_SHARE_LINK', 'link', link.id, { fileId: String(link.fileId) });
  },

  /** Step 1: verify (token, password, policy). Does NOT consume a download. */
  async open(actor: Actor, token: string, password?: string) {
    const { link, file, access } = await resolve(actor, token, password);
    await auditService.record(actor, 'OPEN_SHARE_LINK', 'link', link.id, {
      fileId: file.id, classification: file.classification, roomId: file.dataRoom ? String(file.dataRoom) : undefined,
    });
    return {
      file: toFileDTO(file, access),
      requiresPurpose: access.requiresPurpose,
      expiresAt: link.expiresAt,
      remainingDownloads: link.maxDownloads ? link.maxDownloads - link.currentDownloads : null,
    };
  },

  /** Step 2: verify again, atomically consume one download, deliver (refund on failure). */
  async download(actor: Actor, input: { token: string; password?: string; purpose?: string; reason?: string }) {
    const { link, file, access } = await resolve(actor, input.token, input.password);
    if (access.requiresPurpose && !(input.purpose && input.reason)) {
      throw new AppError('A purpose and reason are required to access confidential files', 428);
    }
    const now = new Date();
    // Atomic gate: concurrent redemptions of a one-time link cannot both win.
    const consumed = await SharedLink.findOneAndUpdate(
      {
        _id: link._id,
        isActive: true,
        expiresAt: { $gt: now },
        $expr: { $or: [{ $eq: [{ $ifNull: ['$maxDownloads', null] }, null] }, { $lt: ['$currentDownloads', '$maxDownloads'] }] },
      },
      { $inc: { currentDownloads: 1 } },
      { new: true },
    );
    if (!consumed) throw INVALID();
    try {
      return await deliverFile({
        actor, file, access, via: 'link', linkId: link.id,
        context: { purpose: input.purpose, reason: input.reason },
      });
    } catch (err) {
      await SharedLink.updateOne({ _id: link._id }, { $inc: { currentDownloads: -1 } });
      throw err;
    }
  },
};
