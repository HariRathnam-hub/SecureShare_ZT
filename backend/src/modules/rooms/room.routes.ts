import { Router } from 'express';
import { authenticate } from '../../middleware/auth';
import { lookupLimiter } from '../../middleware/phase2Limiters';
import { validate } from '../../middleware/validate';
import { idParam, pagination } from '../../utils/validators';
import { roomController as c } from './room.controller';
import { addMemberBody, attachFileBody, createRoomBody, memberParams, roleBody, roomFileParams, updateRoomBody } from './room.validation';

const router = Router();
router.use(authenticate);
const id = validate(idParam, 'params');

router.post('/', validate(createRoomBody), c.create);
router.get('/', c.list);
router.get('/:id', id, c.get);
router.patch('/:id', id, validate(updateRoomBody), c.update);
router.delete('/:id', id, c.remove);

router.post('/:id/members', lookupLimiter, id, validate(addMemberBody), c.addMember);
router.patch('/:id/members/:userId', validate(memberParams, 'params'), validate(roleBody), c.updateMember);
router.delete('/:id/members/:userId', validate(memberParams, 'params'), c.removeMember);

router.post('/:id/files', id, validate(attachFileBody), c.attachFile);
router.delete('/:id/files/:fileId', validate(roomFileParams, 'params'), c.detachFile);

router.get('/:id/audit', id, validate(pagination, 'query'), c.audit);

export default router;
