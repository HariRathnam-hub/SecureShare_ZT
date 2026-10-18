import { createHash, randomUUID } from 'crypto';
import { AppError } from '../../utils/AppError';
import { logger } from '../../utils/logger';
import { getStorage, StorageNotFoundError } from '../../storage';
import { watermarkPdf } from '../../services/watermark.service';
import { Actor, auditService } from '../audit/audit.service';
import type { AccessDecision } from './access-policy.service';
import { authorizeDownload } from './download-policy.service';
import { FileDocument } from './file.model';
import { FileVersion } from './file-version.model';

export interface DeliveryResult {
  buffer: Buffer;
  contentType: string;
  filename: string;
  downloadId: string;
}

export interface PurposeContext {
  purpose?: string;
  reason?: string;
}

/**
 * Final, audited hand-off. Callers have already run their own policy checks (for early, friendly errors);
 * authorizeDownload() re-derives every decision from current state before any bytes are read.
 * Order: re-check + adaptive decision -> read from storage -> integrity check -> watermark ->
 * AUDIT -> return bytes. If the audit write fails, no bytes leave.
 */
export async function deliverFile(p: {
  actor: Actor;
  file: FileDocument;
  /** Caller's earlier decision; superseded by the fresh one computed in authorizeDownload. */
  access: AccessDecision;
  context: PurposeContext;
  via: 'direct' | 'link';
  versionNumber?: number;
  linkId?: string;
}): Promise<DeliveryResult> {
  const { actor } = p;
  if (p.versionNumber && p.versionNumber !== p.file.currentVersion && !p.access.isOwner) {
    throw new AppError('Only the owner can download earlier versions', 403);
  }
  const { file, access, trust } = await authorizeDownload({ actor, file: p.file, via: p.via, linkId: p.linkId, context: p.context });

  if (p.versionNumber && p.versionNumber !== file.currentVersion && !access.isOwner) {
    throw new AppError('Only the owner can download earlier versions', 403);
  }
  const version = await FileVersion.findOne({ fileId: file._id, versionNumber: p.versionNumber ?? file.currentVersion }).select('+storageKey');
  if (!version) throw new AppError('Version not found', 404);

  const roomId = file.dataRoom ? String(file.dataRoom) : undefined;

  const downloadId = randomUUID();
  const timestamp = new Date().toISOString();
  const watermark = { user: actor.email, userId: actor.id, timestamp, ip: actor.ip ?? 'unknown', downloadId };
  const applyWatermark = version.mimeType === 'application/pdf' && !access.isOwner;

  let data: Buffer;
  try {
    data = await getStorage().downloadFile(version.storageKey);
  } catch (err) {
    logger.error('Stored object unreadable', { fileId: file.id, version: version.versionNumber, err });
    await auditService.record(actor, 'ACCESS_DENIED', 'file', file.id, {
      reason: err instanceof StorageNotFoundError ? 'object_missing' : 'storage_error', downloadId,
    });
    throw new AppError('The stored file is unavailable', 500);
  }

  // Assume breach: verify the bytes on disk are the bytes that were uploaded.
  if (createHash('sha256').update(data).digest('hex') !== version.sha256) {
    logger.error('Integrity check failed', { fileId: file.id, version: version.versionNumber });
    await auditService.record(actor, 'ACCESS_DENIED', 'file', file.id, { reason: 'integrity_check_failed', downloadId, version: version.versionNumber });
    throw new AppError('File integrity check failed. The download was blocked.', 500);
  }

  if (applyWatermark) {
    try {
      data = await watermarkPdf(data, watermark);
    } catch (err) {
      logger.error('Watermarking failed; download blocked', { fileId: file.id, err });
      await auditService.record(actor, 'ACCESS_DENIED', 'file', file.id, { reason: 'watermark_failed', downloadId });
      throw new AppError('This PDF cannot be watermarked (encrypted or malformed), so the download is blocked', 422);
    }
  }

  // Audit BEFORE delivery: no record, no bytes.
  await auditService.record(actor, 'DOWNLOAD_FILE', 'file', file.id, {
    downloadId,
    version: version.versionNumber,
    via: p.via,
    linkId: p.linkId,
    classification: file.classification,
    access: access.via,
    purpose: p.context.purpose,
    reason: p.context.reason,
    roomId,
    delivery: applyWatermark ? 'stream-watermarked' : 'stream',
    watermark: { applied: applyWatermark, ...watermark },
    trust: { decision: trust.verdict.decision, risk: trust.risk, device: trust.device },
  });

  return { buffer: data, contentType: version.mimeType, filename: file.fileName, downloadId };
}
