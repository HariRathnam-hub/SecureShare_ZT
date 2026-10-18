import { Router } from 'express';
import { z } from 'zod';
import { authenticate, authorize } from '../../middleware/auth';
import { validate } from '../../middleware/validate';
import { asyncHandler } from '../../utils/asyncHandler';
import { securityService } from './security.service';

const router = Router();
router.use(authenticate, authorize('admin')); // statistics and event feeds are admin-only

const query = z.object({ hours: z.coerce.number().int().min(1).max(720).default(24) });

router.get(
  '/overview',
  validate(query, 'query'),
  asyncHandler(async (req, res) => {
    const { hours } = req.query as unknown as z.infer<typeof query>;
    res.setHeader('Cache-Control', 'no-store');
    res.json({ status: 'success', data: await securityService.overview(hours) });
  }),
);

export default router;
