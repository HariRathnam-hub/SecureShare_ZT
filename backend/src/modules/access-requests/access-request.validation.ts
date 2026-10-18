import { z } from 'zod';
import { PURPOSES } from './access-request.model';

export const createRequestBody = z.object({
  purpose: z.enum(PURPOSES),
  reason: z.string().trim().min(10, 'Explain why you need access (10+ characters)').max(500),
});
export const approveBody = z.object({
  expiresInDays: z.coerce.number().int().min(1).max(30).default(7),
  permission: z.enum(['view', 'download']).default('download'),
  note: z.string().trim().max(300).optional(),
});
export const rejectBody = z.object({ note: z.string().trim().max(300).optional() });
export const boxQuery = z.object({
  box: z.enum(['incoming', 'outgoing']).default('incoming'),
  status: z.enum(['pending', 'approved', 'rejected']).optional(),
});
