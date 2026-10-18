import { HydratedDocument, Schema, Types, model } from 'mongoose';

export const CLASSIFICATIONS = ['public', 'internal', 'confidential', 'restricted'] as const;
export type Classification = (typeof CLASSIFICATIONS)[number];
export const CLASS_RANK: Record<Classification, number> = { public: 0, internal: 1, confidential: 2, restricted: 3 };
export const SHARE_PERMISSIONS = ['view', 'download'] as const;
export type SharePermission = (typeof SHARE_PERMISSIONS)[number];

export interface FileGrant {
  user: Types.ObjectId;
  permission: SharePermission;
  grantedBy: Types.ObjectId;
  grantedAt: Date;
  expiresAt?: Date;
  /** Set when the grant came from an approved AccessRequest. Required for restricted files. */
  requestId?: Types.ObjectId;
}

export interface IFile {
  owner: Types.ObjectId;
  fileName: string; // display / download name (editable)
  originalName: string; // name at first upload (immutable)
  mimeType: string;
  size: number;
  sha256: string;
  storageKey: string; // current version's object key. Never serialised (select:false + DTOs).
  currentVersion: number;
  classification: Classification;
  /** Time lock: non-owners cannot download before availableFrom or after availableUntil. */
  availableFrom?: Date;
  availableUntil?: Date;
  sharedWith: FileGrant[];
  dataRoom?: Types.ObjectId;
  createdAt: Date;
  updatedAt: Date;
}
export type FileDocument = HydratedDocument<IFile>;

const grantSchema = new Schema<FileGrant>(
  {
    user: { type: Schema.Types.ObjectId, ref: 'User', required: true },
    permission: { type: String, enum: SHARE_PERMISSIONS, default: 'download' },
    grantedBy: { type: Schema.Types.ObjectId, ref: 'User', required: true },
    grantedAt: { type: Date, default: Date.now },
    expiresAt: { type: Date },
    requestId: { type: Schema.Types.ObjectId, ref: 'AccessRequest' },
  },
  { _id: false },
);

const schema = new Schema<IFile>(
  {
    owner: { type: Schema.Types.ObjectId, ref: 'User', required: true, index: true },
    fileName: { type: String, required: true, trim: true, maxlength: 150 },
    originalName: { type: String, required: true, maxlength: 150, immutable: true },
    mimeType: { type: String, required: true },
    size: { type: Number, required: true },
    sha256: { type: String, required: true },
    storageKey: { type: String, required: true, select: false },
    currentVersion: { type: Number, default: 1 },
    classification: { type: String, enum: CLASSIFICATIONS, default: 'internal' },
    availableFrom: { type: Date },
    availableUntil: { type: Date },
    sharedWith: { type: [grantSchema], default: [] },
    dataRoom: { type: Schema.Types.ObjectId, ref: 'DataRoom' },
  },
  { timestamps: true },
);
schema.index({ owner: 1, updatedAt: -1 });
schema.index({ 'sharedWith.user': 1 });
schema.index({ dataRoom: 1 });

export const File = model<IFile>('File', schema);
