import { z } from 'zod';
import { objectId } from '../../utils/validators';
import { purposeFields } from '../files/file.validation';

export const createLinkBody = z.object({
  // Every link expires: 1 minute .. 30 days.
  expiresInMinutes: z.coerce.number().int().min(1).max(43_200),
  // maxDownloads: 1 => one-time link. Omit for unlimited (until expiry).
  maxDownloads: z.coerce.number().int().min(1).max(1000).optional(),
  password: z.string().min(8).max(72).optional(),
});
export const linkIdParams = z.object({ id: objectId });
const token = z.string().length(64).regex(/^[a-f0-9]+$/);
export const openLinkBody = z.object({ token, password: z.string().max(72).optional() });
export const downloadLinkBody = openLinkBody.extend(purposeFields);
