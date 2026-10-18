import { Router } from 'express';
import { z } from 'zod';
import { authenticate, authorize } from '../../middleware/auth';
import { validate } from '../../middleware/validate';
import { asyncHandler } from '../../utils/asyncHandler';
import { objectId, pagination } from '../../utils/validators';
import { AUDIT_ACTIONS, TARGET_TYPES } from './audit-log.model';
import { auditService } from './audit.service';

const router = Router();
router.use(authenticate, authorize('admin')); // platform-wide trail: admins only

const query = pagination.extend({
  action: z.enum(AUDIT_ACTIONS).optional(),
  targetType: z.enum(TARGET_TYPES).optional(),
  targetId: objectId.optional(),
  actor: objectId.optional(),
});

router.get(
  '/',
  validate(query, 'query'),
  asyncHandler(async (req, res) => {
    const { page, limit, ...filter } = req.query as unknown as z.infer<typeof query>;
    res.json({ status: 'success', data: await auditService.list(filter, page, limit) });
  }),
);

export default router;
