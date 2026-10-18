import { Schema, Types, model } from 'mongoose';

export interface ISharedLink {
  fileId: Types.ObjectId;
  createdBy: Types.ObjectId;
  tokenHash: string; // SHA-256 of the URL token. Raw token is shown once at creation.
  passwordHash?: string;
  expiresAt: Date;
  maxDownloads?: number | null; // 1 = one-time link
  currentDownloads: number;
  failedAttempts: number;
  isActive: boolean;
  createdAt: Date;
}

const schema = new Schema<ISharedLink>(
  {
    fileId: { type: Schema.Types.ObjectId, ref: 'File', required: true, index: true },
    createdBy: { type: Schema.Types.ObjectId, ref: 'User', required: true, index: true },
    tokenHash: { type: String, required: true, unique: true, select: false },
    passwordHash: { type: String, select: false },
    expiresAt: { type: Date, required: true },
    maxDownloads: { type: Number, default: null, min: 1 },
    currentDownloads: { type: Number, default: 0 },
    failedAttempts: { type: Number, default: 0 },
    isActive: { type: Boolean, default: true },
    createdAt: { type: Date, default: Date.now },
  },
  { versionKey: false },
);

export const SharedLink = model<ISharedLink>('SharedLink', schema);
