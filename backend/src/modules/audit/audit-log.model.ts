import { Schema, Types, model } from 'mongoose';

export const AUDIT_ACTIONS = [
  'UPLOAD_FILE', 'UPLOAD_VERSION', 'UPDATE_FILE', 'DOWNLOAD_FILE', 'DELETE_FILE',
  'SHARE_FILE_USER', 'REVOKE_FILE_SHARE',
  'CREATE_SHARE_LINK', 'OPEN_SHARE_LINK', 'REVOKE_SHARE_LINK',
  'ACCESS_REQUEST', 'APPROVE_ACCESS', 'REJECT_ACCESS', 'ACCESS_DENIED',
  'CREATE_ROOM', 'UPDATE_ROOM', 'DELETE_ROOM',
  'ADD_ROOM_MEMBER', 'UPDATE_ROOM_MEMBER', 'REMOVE_ROOM_MEMBER', 'ADD_ROOM_FILE', 'REMOVE_ROOM_FILE',
  // Phase 3: adaptive Zero Trust
  'LOGIN_SUCCESS', 'LOGIN_FAILED', 'SESSION_REVOKED', 'POLICY_DECISION',
  // Hardening: bot challenge, rate limiting, rejected uploads
  'TURNSTILE_FAILED', 'RATE_LIMITED', 'UPLOAD_REJECTED',
] as const;
export type AuditAction = (typeof AUDIT_ACTIONS)[number];
export const TARGET_TYPES = ['file', 'link', 'room', 'accessRequest', 'user', 'system'] as const;
export type TargetType = (typeof TARGET_TYPES)[number];

export interface IAuditLog {
  actor?: Types.ObjectId;
  action: AuditAction;
  targetType: TargetType;
  targetId: Types.ObjectId;
  ip?: string;
  userAgent?: string;
  metadata: Record<string, unknown>;
  timestamp: Date;
}

const schema = new Schema<IAuditLog>(
  {
    actor: { type: Schema.Types.ObjectId, ref: 'User', immutable: true },
    action: { type: String, enum: AUDIT_ACTIONS, required: true, immutable: true },
    targetType: { type: String, enum: TARGET_TYPES, required: true, immutable: true },
    targetId: { type: Schema.Types.ObjectId, required: true, immutable: true },
    ip: { type: String, maxlength: 64, immutable: true },
    userAgent: { type: String, maxlength: 300, immutable: true },
    metadata: { type: Schema.Types.Mixed, default: {}, immutable: true },
    timestamp: { type: Date, default: Date.now, immutable: true },
  },
  { versionKey: false },
);

schema.index({ targetType: 1, targetId: 1, timestamp: -1 });
schema.index({ 'metadata.roomId': 1, timestamp: -1 }, { sparse: true });
schema.index({ actor: 1, timestamp: -1 });
schema.index({ action: 1, timestamp: -1 });

// Append-only: any mutation path throws.
const blocked = ['updateOne', 'updateMany', 'findOneAndUpdate', 'findOneAndReplace', 'replaceOne', 'deleteOne', 'deleteMany', 'findOneAndDelete'] as const;
schema.pre(blocked as unknown as 'updateOne', function () {
  throw new Error('AuditLog is append-only');
});
schema.pre('save', function (next) {
  if (!this.isNew) return next(new Error('AuditLog is append-only'));
  next();
});

export const AuditLog = model<IAuditLog>('AuditLog', schema);
