import { z } from 'zod';
import { objectId } from '../../utils/validators';
import { ROOM_MAX_CLASSIFICATIONS, ROOM_ROLES } from './data-room.model';

const permissions = z.object({
  viewerCanDownload: z.boolean(),
  maxClassification: z.enum(ROOM_MAX_CLASSIFICATIONS),
});
export const createRoomBody = z.object({
  name: z.string().trim().min(2).max(100),
  description: z.string().trim().max(500).optional(),
  permissions: permissions.partial().optional(),
});
export const updateRoomBody = z
  .object({ name: z.string().trim().min(2).max(100), description: z.string().trim().max(500), permissions: permissions.partial() })
  .partial()
  .refine((v) => Object.keys(v).length > 0, 'Nothing to update');
export const addMemberBody = z.object({ email: z.string().trim().toLowerCase().email(), role: z.enum(ROOM_ROLES).default('viewer') });
export const roleBody = z.object({ role: z.enum(ROOM_ROLES) });
export const attachFileBody = z.object({ fileId: objectId });
export const memberParams = z.object({ id: objectId, userId: objectId });
export const roomFileParams = z.object({ id: objectId, fileId: objectId });
