import { Router } from 'express';
import { authenticate } from '../../middleware/auth';
import { linkLimiter } from '../../middleware/phase2Limiters';
import { validate } from '../../middleware/validate';
import { linkController as c } from './link.controller';
import { downloadLinkBody, linkIdParams, openLinkBody } from './link.validation';

const router = Router();
router.use(authenticate);

router.get('/', c.listMine);
router.delete('/:id', validate(linkIdParams, 'params'), c.revoke);
// Token travels in the body (never the URL) so it stays out of access logs.
router.post('/open', linkLimiter, validate(openLinkBody), c.open);
router.post('/download', linkLimiter, validate(downloadLinkBody), c.download);

export default router;
