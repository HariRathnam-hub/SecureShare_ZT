import { AppError } from '../../utils/AppError';
import { Actor, auditService } from '../audit/audit.service';
import { toFileDTO } from '../files/file.dto';
import { CLASS_RANK, File } from '../files/file.model';
import { User } from '../user/user.model';
import { DataRoom, DataRoomDocument, RoomRole, roomRole } from './data-room.model';

const NOT_FOUND = () => new AppError('Data room not found', 404);
const RANK: Record<RoomRole, number> = { viewer: 0, editor: 1, manager: 2 };

/** Load a room and the actor's role. Non-members get 404 (room existence is not revealed). */
async function loadRoom(actor: Actor, id: string, min: RoomRole = 'viewer') {
  const room = await DataRoom.findById(id);
  const role = room ? roomRole(room, actor.id) : null;
  if (!room || !role) throw NOT_FOUND();
  if (RANK[role] < RANK[min]) {
    await auditService.record(actor, 'ACCESS_DENIED', 'room', room.id, { need: min, role });
    throw new AppError('Your room role does not allow this', 403);
  }
  return { room, role };
}

const person = (u: any) => (u?.name ? { id: String(u._id), name: u.name, email: u.email } : { id: String(u?._id ?? u) });

async function toRoomDTO(room: DataRoomDocument, role: RoomRole, detail = false) {
  const base = {
    id: room.id as string,
    name: room.name,
    description: room.description ?? '',
    permissions: { viewerCanDownload: room.permissions.viewerCanDownload, maxClassification: room.permissions.maxClassification },
    myRole: role,
    memberCount: room.members.length + 1,
    createdAt: room.createdAt,
  };
  if (!detail) return { ...base, fileCount: await File.countDocuments({ dataRoom: room._id }) };
  await room.populate([{ path: 'owner', select: 'name email' }, { path: 'members.user', select: 'name email' }]);
  const files = await File.find({ dataRoom: room._id }).sort({ updatedAt: -1 }).populate('owner', 'name email');
  return {
    ...base,
    fileCount: files.length,
    owner: person(room.owner),
    members: room.members.map((m: any) => ({ user: person(m.user), role: m.role, addedAt: m.addedAt })),
    files: files.map((f) => toFileDTO(f)),
  };
}

export const roomService = {
  async create(actor: Actor, input: { name: string; description?: string; permissions?: Partial<DataRoomDocument['permissions']> }) {
    const room = await DataRoom.create({ name: input.name, description: input.description, owner: actor.id, permissions: input.permissions });
    await auditService.record(actor, 'CREATE_ROOM', 'room', room.id, { name: room.name, roomId: room.id });
    return toRoomDTO(room, 'manager');
  },

  async list(actor: Actor) {
    const rooms = await DataRoom.find({ $or: [{ owner: actor.id }, { 'members.user': actor.id }] }).sort({ updatedAt: -1 });
    return Promise.all(rooms.map((r) => toRoomDTO(r, roomRole(r, actor.id)!)));
  },

  async get(actor: Actor, id: string) {
    const { room, role } = await loadRoom(actor, id);
    return toRoomDTO(room, role, true);
  },

  async update(actor: Actor, id: string, patch: { name?: string; description?: string; permissions?: Partial<DataRoomDocument['permissions']> }) {
    const { room, role } = await loadRoom(actor, id, 'manager');
    if (patch.permissions?.maxClassification) {
      const limit = CLASS_RANK[patch.permissions.maxClassification];
      const tooHigh = await File.exists({ dataRoom: room._id, classification: { $in: Object.keys(CLASS_RANK).filter((c) => CLASS_RANK[c as keyof typeof CLASS_RANK] > limit) } });
      if (tooHigh) throw new AppError('The room contains files above that classification', 409);
    }
    if (patch.name) room.name = patch.name;
    if (patch.description !== undefined) room.description = patch.description;
    if (patch.permissions?.viewerCanDownload !== undefined) room.permissions.viewerCanDownload = patch.permissions.viewerCanDownload;
    if (patch.permissions?.maxClassification) room.permissions.maxClassification = patch.permissions.maxClassification;
    await room.save();
    await auditService.record(actor, 'UPDATE_ROOM', 'room', room.id, { patch, roomId: room.id });
    return toRoomDTO(room, role, true);
  },

  async remove(actor: Actor, id: string) {
    const { room } = await loadRoom(actor, id, 'manager');
    if (String(room.owner) !== actor.id) throw new AppError('Only the room owner can delete it', 403);
    await auditService.record(actor, 'DELETE_ROOM', 'room', room.id, { name: room.name, roomId: room.id });
    await File.updateMany({ dataRoom: room._id }, { $unset: { dataRoom: 1 } });
    await DataRoom.deleteOne({ _id: room._id });
  },

  async addMember(actor: Actor, id: string, input: { email: string; role: RoomRole }) {
    const { room, role } = await loadRoom(actor, id, 'manager');
    if (input.role === 'manager' && role !== 'manager') throw new AppError('Only managers can add managers', 403);
    const target = await User.findOne({ email: input.email, isActive: true, isEmailVerified: true });
    if (!target) throw new AppError('No active user with that email', 404);
    if (roomRole(room, target.id)) throw new AppError('Already a member of this room', 409);
    room.members.push({ user: target._id, role: input.role, addedBy: actor.id as any, addedAt: new Date() });
    await room.save();
    await auditService.record(actor, 'ADD_ROOM_MEMBER', 'room', room.id, { member: target.id, email: target.email, role: input.role, roomId: room.id });
  },

  async updateMember(actor: Actor, id: string, userId: string, newRole: RoomRole) {
    const { room } = await loadRoom(actor, id, 'manager');
    const m = room.members.find((x) => String(x.user) === userId);
    if (!m) throw new AppError('Member not found', 404);
    const before = m.role;
    m.role = newRole;
    await room.save();
    await auditService.record(actor, 'UPDATE_ROOM_MEMBER', 'room', room.id, { member: userId, from: before, to: newRole, roomId: room.id });
  },

  async removeMember(actor: Actor, id: string, userId: string) {
    const { room, role } = await loadRoom(actor, id);
    if (userId !== actor.id && role !== 'manager') throw new AppError('Your room role does not allow this', 403);
    if (!room.members.some((m) => String(m.user) === userId)) throw new AppError('Member not found', 404);
    room.members = room.members.filter((m) => String(m.user) !== userId) as any;
    await room.save();
    await auditService.record(actor, 'REMOVE_ROOM_MEMBER', 'room', room.id, { member: userId, self: userId === actor.id, roomId: room.id });
  },

  async attachFile(actor: Actor, id: string, fileId: string) {
    const { room } = await loadRoom(actor, id, 'editor');
    const file = await File.findOne({ _id: fileId, owner: actor.id }); // only your own files
    if (!file) throw new AppError('File not found', 404);
    if (file.dataRoom) throw new AppError('The file is already in a data room', 409);
    if (CLASS_RANK[file.classification] > CLASS_RANK[room.permissions.maxClassification]) {
      throw new AppError(`This room does not accept ${file.classification} files`, 400);
    }
    file.dataRoom = room._id;
    await file.save();
    await auditService.record(actor, 'ADD_ROOM_FILE', 'room', room.id, { fileId: file.id, name: file.fileName, roomId: room.id });
  },

  async detachFile(actor: Actor, id: string, fileId: string) {
    const { room, role } = await loadRoom(actor, id, 'viewer');
    const file = await File.findOne({ _id: fileId, dataRoom: room._id });
    if (!file) throw new AppError('File not found in this room', 404);
    if (String(file.owner) !== actor.id && role !== 'manager') throw new AppError('Your room role does not allow this', 403);
    file.dataRoom = undefined;
    await file.save();
    await auditService.record(actor, 'REMOVE_ROOM_FILE', 'room', room.id, { fileId: file.id, name: file.fileName, roomId: room.id });
  },

  async audit(actor: Actor, id: string, page: number, limit: number) {
    const { room } = await loadRoom(actor, id, 'manager');
    return auditService.list({ $or: [{ targetType: 'room', targetId: room._id }, { 'metadata.roomId': room.id }] }, page, limit);
  },
};
