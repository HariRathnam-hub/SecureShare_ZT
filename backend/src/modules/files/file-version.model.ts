import { Schema, Types, model } from 'mongoose';

export interface IFileVersion {
  fileId: Types.ObjectId;
  versionNumber: number;
  storageKey: string;
  uploadedBy: Types.ObjectId;
  originalName: string;
  mimeType: string;
  size: number;
  sha256: string;
  createdAt: Date;
}

const schema = new Schema<IFileVersion>(
  {
    fileId: { type: Schema.Types.ObjectId, ref: 'File', required: true },
    versionNumber: { type: Number, required: true },
    storageKey: { type: String, required: true, select: false },
    uploadedBy: { type: Schema.Types.ObjectId, ref: 'User', required: true },
    originalName: { type: String, required: true },
    mimeType: { type: String, required: true },
    size: { type: Number, required: true },
    sha256: { type: String, required: true },
    createdAt: { type: Date, default: Date.now },
  },
  { versionKey: false },
);
schema.index({ fileId: 1, versionNumber: 1 }, { unique: true });

export const FileVersion = model<IFileVersion>('FileVersion', schema);
