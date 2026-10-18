import { asyncHandler } from '../../utils/asyncHandler';
import { actorFrom } from '../audit/audit.service';
import { accessRequestService as s } from './access-request.service';

export const accessRequestController = {
  create: asyncHandler(async (req, res) => {
    res.status(201).json({ status: 'success', data: { request: await s.create(actorFrom(req), req.params.id, req.body) } });
  }),
  list: asyncHandler(async (req, res) => {
    res.json({ status: 'success', data: { requests: await s.list(actorFrom(req), req.query as any) } });
  }),
  approve: asyncHandler(async (req, res) => {
    res.json({ status: 'success', data: { request: await s.approve(actorFrom(req), req.params.id, req.body) } });
  }),
  reject: asyncHandler(async (req, res) => {
    res.json({ status: 'success', data: { request: await s.reject(actorFrom(req), req.params.id, req.body) } });
  }),
};
