import { Router } from 'express';
import { z } from 'zod';
import { authenticate, authorize } from '../../middleware/auth';
import { validate } from '../../middleware/validate';
import { AppError } from '../../utils/AppError';
import { asyncHandler } from '../../utils/asyncHandler';
import { logger } from '../../utils/logger';
import { ROLES, User } from './user.model';

const router = Router();
router.use(authenticate);

router.get(
  '/me',
  asyncHandler(async (req, res) => {
    const user = await User.findById(req.user!.id);
    res.json({ status: 'success', data: { user } });
  }),
);

// ---- Admin only (RBAC) ----
const listQuery = z.object({
  page: z.coerce.number().int().min(1).default(1),
  limit: z.coerce.number().int().min(1).max(100).default(20),
});
const idParam = z.object({ id: z.string().regex(/^[a-f\d]{24}$/i) });
const roleBody = z.object({ role: z.enum(ROLES) });

router.get(
  '/',
  authorize('admin'),
  validate(listQuery, 'query'),
  asyncHandler(async (req, res) => {
    const { page, limit } = req.query as unknown as z.infer<typeof listQuery>;
    const [users, total] = await Promise.all([
      User.find().sort({ createdAt: -1 }).skip((page - 1) * limit).limit(limit),
      User.countDocuments(),
    ]);
    res.json({ status: 'success', data: { users, page, limit, total } });
  }),
);

router.patch(
  '/:id/role',
  authorize('admin'),
  validate(idParam, 'params'),
  validate(roleBody),
  asyncHandler(async (req, res) => {
    if (req.params.id === req.user!.id) throw new AppError('You cannot change your own role', 400);
    const user = await User.findByIdAndUpdate(req.params.id, { role: req.body.role }, { new: true });
    if (!user) throw new AppError('User not found', 404);
    logger.info('Role changed', { actor: req.user!.id, target: user.id, role: user.role });
    res.json({ status: 'success', data: { user } });
  }),
);

export default router;
