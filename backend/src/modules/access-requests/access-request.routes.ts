import { Router } from 'express';
import { authenticate } from '../../middleware/auth';
import { validate } from '../../middleware/validate';
import { idParam } from '../../utils/validators';
import { accessRequestController as c } from './access-request.controller';
import { approveBody, boxQuery, rejectBody } from './access-request.validation';

const router = Router();
router.use(authenticate);

router.get('/', validate(boxQuery, 'query'), c.list);
router.post('/:id/approve', validate(idParam, 'params'), validate(approveBody), c.approve);
router.post('/:id/reject', validate(idParam, 'params'), validate(rejectBody), c.reject);

export default router;
