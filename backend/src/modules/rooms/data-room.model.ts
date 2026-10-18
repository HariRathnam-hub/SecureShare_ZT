import { HydratedDocument, Schema, Types, model } from 'mongoose';

export const ROOM_ROLES = ['viewer', 'editor', 'manager'] as const;
export type RoomRole = (typeof ROOM_ROLES)[number];
export const ROOM_MAX_CLASSIFICATIONS = ['public', 'internal', 'confidential'] as const;

export interface RoomMember {
  user: Types.ObjectId;
  role: RoomRole;
  addedBy: Types.ObjectId;
  addedAt: Date;
}
export interface IDataRoom {
  name: string;
  description?: string;
  owner: Types.ObjectId;
  members: RoomMember[]; // excludes the owner, who is an implicit manager
  permissions: {
    viewerCanDownload: boolean;
    maxClassification: (typeof ROOM_MAX_CLASSIFICATIONS)[number];
  };
  createdAt: Date;
  updatedAt: Date;
}
export type DataRoomDocument = HydratedDocument<IDataRoom>;

const memberSchema = new Schema<RoomMember>(
  {
    user: { type: Schema.Types.ObjectId, ref: 'User', required: true },
    role: { type: String, enum: ROOM_ROLES, default: 'viewer' },
    addedBy: { type: Schema.Types.ObjectId, ref: 'User', required: true },
    addedAt: { type: Date, default: Date.now },
  },
  { _id: false },
);

const schema = new Schema<IDataRoom>(
  {
    name: { type: String, required: true, trim: true, minlength: 2, maxlength: 100 },
    description: { type: String, trim: true, maxlength: 500 },
    owner: { type: Schema.Types.ObjectId, ref: 'User', required: true, index: true },
    members: { type: [memberSchema], default: [] },
    permissions: {
      viewerCanDownload: { type: Boolean, default: true },
      maxClassification: { type: String, enum: ROOM_MAX_CLASSIFICATIONS, default: 'confidential' },
    },
  },
  { timestamps: true },
);
schema.index({ 'members.user': 1 });

export const DataRoom = model<IDataRoom>('DataRoom', schema);

/** Owner is an implicit manager. Returns null for non-members. */
export function roomRole(room: Pick<IDataRoom, 'owner' | 'members'>, userId: string): RoomRole | null {
  if (String(room.owner) === userId) return 'manager';
  return room.members.find((m) => String(m.user) === userId)?.role ?? null;
}
