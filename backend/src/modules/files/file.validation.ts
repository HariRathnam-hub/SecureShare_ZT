import { z } from 'zod';
import { sanitizeFileName } from '../../utils/filename';
import { objectId } from '../../utils/validators';
import { CLASSIFICATIONS, SHARE_PERMISSIONS } from './file.model';

const email = z.string().trim().toLowerCase().email().max(254);
const isoDate = z.coerce.date();
/** Multipart fields arrive as strings; treat empty as absent. */
const optionalDate = z.preprocess((v) => (v === '' || v === null ? undefined : v), z.coerce.date().optional());

export const uploadBody = z.object({
  classification: z.enum(CLASSIFICATIONS).default('internal'),
  roomId: z.preprocess((v) => (v === '' ? undefined : v), objectId.optional()),
  availableFrom: optionalDate,
  availableUntil: optionalDate,
}).refine((v) => !v.availableFrom || !v.availableUntil || v.availableUntil > v.availableFrom, {
  path: ['availableUntil'],
  message: 'availableUntil must be after availableFrom',
});

export const updateFileBody = z
  .object({
    // Display/download name only (never a storage path). Sanitised: no path parts, control/bidi characters, leading dots.
    fileName: z.string().trim().min(1).max(120).transform(sanitizeFileName).optional(),
    classification: z.enum(CLASSIFICATIONS).optional(),
    // null clears that side of the time lock
    availableFrom: isoDate.nullable().optional(),
    availableUntil: isoDate.nullable().optional(),
  })
  .refine((v) => Object.keys(v).length > 0, 'Nothing to update')
  .refine((v) => !v.availableFrom || !v.availableUntil || v.availableUntil > v.availableFrom, {
    path: ['availableUntil'],
    message: 'availableUntil must be after availableFrom',
  });

export const listQuery = z.object({
  scope: z.enum(['owned', 'shared']).default('owned'),
  q: z.string().trim().max(100).optional(),
  page: z.coerce.number().int().min(1).default(1),
  limit: z.coerce.number().int().min(1).max(100).default(20),
});

/** Purpose context: required for confidential downloads by non-owners. */
export const purposeFields = {
  purpose: z.enum(['project', 'research', 'audit', 'compliance', 'education', 'other']).optional(),
  reason: z.string().trim().min(10).max(500).optional(),
};
export const downloadBody = z.object({ version: z.coerce.number().int().min(1).optional(), ...purposeFields });

export const shareUserBody = z.object({
  email,
  permission: z.enum(SHARE_PERMISSIONS).default('download'),
  expiresAt: isoDate.optional(),
});

export const fileUserParams = z.object({ id: objectId, userId: objectId });
