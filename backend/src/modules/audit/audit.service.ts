import { Request } from 'express';
import { FilterQuery, Types } from 'mongoose';
import type { DeviceContext, EdgeIdentity } from '../../security/types';
import type { Role } from '../user/user.model';
import { AuditAction, AuditLog, IAuditLog, TargetType } from './audit-log.model';

export interface Actor {
  id: string;
  email: string;
  role: Role;
  ip?: string;
  userAgent?: string;
  /** Phase 3: device + edge identity attached by middleware; undefined until then. */
  device?: DeviceContext;
  edge?: EdgeIdentity;
}

/** targetId for events with no real target (e.g. a failed login for an email that has no account). */
export const SYSTEM_TARGET_ID = new Types.ObjectId('000000000000000000000000');

export const actorFrom = (req: Request): Actor => ({
  id: req.user!.id,
  email: req.user!.email,
  role: req.user!.role,
  ip: req.ip,
  userAgent: req.get('user-agent')?.slice(0, 300),
  device: req.trust?.device,
  edge: req.trust?.edge,
});

export const auditService = {
  /** Awaited by callers: if the audit write fails, the action fails (fail closed). */
  record(
    actor: { id?: string; ip?: string; userAgent?: string } | null,
    action: AuditAction,
    targetType: TargetType,
    targetId: string | Types.ObjectId,
    metadata: Record<string, unknown> = {},
  ) {
    return AuditLog.create({
      actor: actor?.id,
      action,
      targetType,
      targetId,
      ip: actor?.ip,
      userAgent: actor?.userAgent,
      metadata,
    });
  },

  async list(filter: FilterQuery<IAuditLog>, page: number, limit: number) {
    const [items, total] = await Promise.all([
      AuditLog.find(filter)
        .sort({ timestamp: -1 })
        .skip((page - 1) * limit)
        .limit(limit)
        .populate('actor', 'name email')
        .lean(),
      AuditLog.countDocuments(filter),
    ]);
    return {
      total,
      page,
      limit,
      items: items.map((a: any) => ({
        id: String(a._id),
        actor: a.actor ? { id: String(a.actor._id), name: a.actor.name, email: a.actor.email } : null,
        action: a.action,
        targetType: a.targetType,
        targetId: String(a.targetId),
        ip: a.ip,
        userAgent: a.userAgent,
        metadata: a.metadata,
        timestamp: a.timestamp,
      })),
    };
  },
};
