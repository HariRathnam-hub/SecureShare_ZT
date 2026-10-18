import { asyncHandler } from '../../utils/asyncHandler';
import { actorFrom } from '../audit/audit.service';
import { roomService as s } from './room.service';

const ok = (data: unknown) => ({ status: 'success', data });

export const roomController = {
  create: asyncHandler(async (req, res) => res.status(201).json(ok({ room: await s.create(actorFrom(req), req.body) }))),
  list: asyncHandler(async (req, res) => res.json(ok({ rooms: await s.list(actorFrom(req)) }))),
  get: asyncHandler(async (req, res) => res.json(ok({ room: await s.get(actorFrom(req), req.params.id) }))),
  update: asyncHandler(async (req, res) => res.json(ok({ room: await s.update(actorFrom(req), req.params.id, req.body) }))),
  remove: asyncHandler(async (req, res) => {
    await s.remove(actorFrom(req), req.params.id);
    res.status(204).end();
  }),
  addMember: asyncHandler(async (req, res) => {
    await s.addMember(actorFrom(req), req.params.id, req.body);
    res.status(201).json({ status: 'success', message: 'Member added' });
  }),
  updateMember: asyncHandler(async (req, res) => {
    await s.updateMember(actorFrom(req), req.params.id, req.params.userId, req.body.role);
    res.json({ status: 'success', message: 'Role updated' });
  }),
  removeMember: asyncHandler(async (req, res) => {
    await s.removeMember(actorFrom(req), req.params.id, req.params.userId);
    res.status(204).end();
  }),
  attachFile: asyncHandler(async (req, res) => {
    await s.attachFile(actorFrom(req), req.params.id, req.body.fileId);
    res.status(201).json({ status: 'success', message: 'File added to room' });
  }),
  detachFile: asyncHandler(async (req, res) => {
    await s.detachFile(actorFrom(req), req.params.id, req.params.fileId);
    res.status(204).end();
  }),
  audit: asyncHandler(async (req, res) => {
    const { page, limit } = req.query as any;
    res.json(ok(await s.audit(actorFrom(req), req.params.id, page, limit)));
  }),
};
