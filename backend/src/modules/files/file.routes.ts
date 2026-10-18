import { Router } from 'express';
import { z } from 'zod';
import { authenticate } from '../../middleware/auth';
import { downloadLimiter, shareLimiter, uploadLimiter } from '../../middleware/phase2Limiters';
import { validate } from '../../middleware/validate';
import { asyncHandler } from '../../utils/asyncHandler';
import { idParam, pagination } from '../../utils/validators';
import { actorFrom } from '../audit/audit.service';
import { accessRequestController } from '../access-requests/access-request.controller';
import { createRequestBody } from '../access-requests/access-request.validation';
import { linkController } from '../links/link.controller';
import { createLinkBody } from '../links/link.validation';
import { fileController as c } from './file.controller';
import { downloadBody, fileUserParams, listQuery, shareUserBody, updateFileBody, uploadBody } from './file.validation';
import { loadAuthorised } from './file.service';
import { uploadSingle } from './upload';

const router = Router();
router.use(authenticate); // every file route: authenticated first

const id = validate(idParam, 'params');
/** Authorise BEFORE buffering a multipart body, so a non-owner is rejected without streaming up to MAX_UPLOAD_MB into memory. */
const ownerGate = asyncHandler(async (req, _res, next) => {
  await loadAuthorised(actorFrom(req), req.params.id, 'owner');
  next();
});

router.post('/', uploadLimiter, uploadSingle, validate(uploadBody), c.upload);
router.get('/', validate(listQuery, 'query'), c.list);
router.get('/:id', id, c.get);
router.patch('/:id', id, validate(updateFileBody), c.update);
router.delete('/:id', id, c.remove);

router.post('/:id/versions', uploadLimiter, id, ownerGate, uploadSingle, c.addVersion);
router.post('/:id/download', downloadLimiter, id, validate(downloadBody), c.download);

router.post('/:id/shares', shareLimiter, id, validate(shareUserBody), c.share);
router.delete('/:id/shares/:userId', validate(fileUserParams, 'params'), c.revokeShare);

router.post('/:id/links', shareLimiter, id, validate(createLinkBody), linkController.create);
router.post('/:id/access-requests', shareLimiter, id, validate(createRequestBody), accessRequestController.create);
router.get('/:id/audit', id, validate(pagination.extend({ limit: z.coerce.number().int().min(1).max(100).default(50) }), 'query'), c.audit);

export default router;
