import { Response } from 'express';
import { asyncHandler } from '../../utils/asyncHandler';
import { actorFrom, auditService } from '../audit/audit.service';
import { attachmentDisposition } from '../../utils/filename';
import type { DeliveryResult } from './delivery.service';
import { fileService, loadAuthorised } from './file.service';
import { isAllowedMime } from './upload';

/**
 * Every file leaves the API as a forced download, never as something a browser may render:
 *  - attachment + sanitised filename (no header injection),
 *  - Content-Type only from the upload allow-list (anything else, e.g. a tampered DB row, becomes octet-stream),
 *  - nosniff, a sandboxing CSP, no caching.
 */
export function sendDelivery(res: Response, d: DeliveryResult) {
  res.set({
    'Cache-Control': 'no-store',
    'Content-Type': isAllowedMime(d.contentType) ? d.contentType : 'application/octet-stream',
    'Content-Disposition': attachmentDisposition(d.filename),
    'X-Content-Type-Options': 'nosniff',
    'Content-Security-Policy': "default-src 'none'; frame-ancestors 'none'; sandbox",
    'X-Download-Id': d.downloadId,
  });
  return res.send(d.buffer);
}

export const fileController = {
  upload: asyncHandler(async (req, res) => {
    const file = await fileService.upload(actorFrom(req), req.file, req.body);
    res.status(201).json({ status: 'success', data: { file } });
  }),
  addVersion: asyncHandler(async (req, res) => {
    const file = await fileService.addVersion(actorFrom(req), req.params.id, req.file);
    res.status(201).json({ status: 'success', data: { file } });
  }),
  list: asyncHandler(async (req, res) => {
    res.json({ status: 'success', data: await fileService.list(actorFrom(req), req.query as any) });
  }),
  get: asyncHandler(async (req, res) => {
    res.json({ status: 'success', data: await fileService.get(actorFrom(req), req.params.id) });
  }),
  update: asyncHandler(async (req, res) => {
    res.json({ status: 'success', data: { file: await fileService.update(actorFrom(req), req.params.id, req.body) } });
  }),
  remove: asyncHandler(async (req, res) => {
    await fileService.remove(actorFrom(req), req.params.id);
    res.status(204).end();
  }),
  download: asyncHandler(async (req, res) => {
    sendDelivery(res, await fileService.download(actorFrom(req), req.params.id, req.body));
  }),
  share: asyncHandler(async (req, res) => {
    await fileService.shareWithUser(actorFrom(req), req.params.id, req.body);
    res.status(201).json({ status: 'success', message: 'Shared' });
  }),
  revokeShare: asyncHandler(async (req, res) => {
    await fileService.revokeShare(actorFrom(req), req.params.id, req.params.userId);
    res.status(204).end();
  }),
  audit: asyncHandler(async (req, res) => {
    const actor = actorFrom(req);
    const { file } = await loadAuthorised(actor, req.params.id, 'owner');
    const { page, limit } = req.query as any;
    res.json({ status: 'success', data: await auditService.list({ targetType: 'file', targetId: file._id }, page, limit) });
  }),
};

