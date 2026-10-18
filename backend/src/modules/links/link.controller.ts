import { asyncHandler } from '../../utils/asyncHandler';
import { actorFrom } from '../audit/audit.service';
import { sendDelivery } from '../files/file.controller';
import { linkService } from './link.service';

export const linkController = {
  create: asyncHandler(async (req, res) => {
    const data = await linkService.create(actorFrom(req), req.params.id, req.body);
    res.setHeader('Cache-Control', 'no-store');
    res.status(201).json({ status: 'success', data });
  }),
  listMine: asyncHandler(async (req, res) => {
    res.json({ status: 'success', data: { links: await linkService.listMine(actorFrom(req)) } });
  }),
  revoke: asyncHandler(async (req, res) => {
    await linkService.revoke(actorFrom(req), req.params.id);
    res.status(204).end();
  }),
  open: asyncHandler(async (req, res) => {
    const { token, password } = req.body;
    res.json({ status: 'success', data: await linkService.open(actorFrom(req), token, password) });
  }),
  download: asyncHandler(async (req, res) => {
    sendDelivery(res, await linkService.download(actorFrom(req), req.body));
  }),
};
