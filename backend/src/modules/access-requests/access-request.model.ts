import { Schema, Types, model } from 'mongoose';

export const PURPOSES = ['project', 'research', 'audit', 'compliance', 'education', 'other'] as const;
export type Purpose = (typeof PURPOSES)[number];
export const REQUEST_STATUSES = ['pending', 'approved', 'rejected'] as const;

export interface IAccessRequest {
  fileId: Types.ObjectId;
  fileOwner: Types.ObjectId;
  requester: Types.ObjectId;
  purpose: Purpose;
  reason: string;
  status: (typeof REQUEST_STATUSES)[number];
  reviewedBy?: Types.ObjectId;
  reviewedAt?: Date;
  decisionNote?: string;
  expiresAt?: Date; // grant expiry set on approval
  createdAt: Date;
}

const schema = new Schema<IAccessRequest>(
  {
    fileId: { type: Schema.Types.ObjectId, ref: 'File', required: true, index: true },
    fileOwner: { type: Schema.Types.ObjectId, ref: 'User', required: true, index: true },
    requester: { type: Schema.Types.ObjectId, ref: 'User', required: true, index: true },
    purpose: { type: String, enum: PURPOSES, required: true },
    reason: { type: String, required: true, trim: true, minlength: 10, maxlength: 500 },
    status: { type: String, enum: REQUEST_STATUSES, default: 'pending' },
    reviewedBy: { type: Schema.Types.ObjectId, ref: 'User' },
    reviewedAt: { type: Date },
    decisionNote: { type: String, maxlength: 300 },
    expiresAt: { type: Date },
    createdAt: { type: Date, default: Date.now },
  },
  { versionKey: false },
);
// One pending request per (file, requester).
schema.index({ fileId: 1, requester: 1 }, { unique: true, partialFilterExpression: { status: 'pending' } });

export const AccessRequest = model<IAccessRequest>('AccessRequest', schema);
