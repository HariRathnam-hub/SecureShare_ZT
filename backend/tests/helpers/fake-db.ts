/**
 * In-memory stand-ins for the handful of Mongoose operations the auth/file flows use, so route-level tests run without a
 * database. Behaviour mirrors the real queries these services issue; anything unexpected throws loudly.
 */
import { Types } from 'mongoose';

type Doc = Record<string, any>;
const q = (value: unknown) => {
  const self: any = { select: () => self, lean: () => self, populate: () => self, sort: () => self, skip: () => self, limit: () => self, then: (a: any, b: any) => Promise.resolve(value).then(a, b) };
  return self;
};

export function installFakeDb(modules: { User: any; AuditLog: any }) {
  const { User, AuditLog } = modules;
  const users: Doc[] = [];
  const audits: Doc[] = [];

  const makeUser = (o: { email: string; password: string; name?: string; role?: string; verified?: boolean; active?: boolean }): Doc => {
    const _id = new Types.ObjectId();
    const u: Doc = {
      _id, id: String(_id), name: o.name ?? 'Test User', email: o.email, role: o.role ?? 'user', isActive: o.active ?? true,
      isEmailVerified: o.verified ?? true, refreshTokens: [], _pw: o.password,
      comparePassword: async (p: string) => p === u._pw,
      save: async () => u,
      // mirrors the real schema's toJSON transform (password, refreshTokens and tokens are never serialised)
      toJSON: () => ({ id: u.id, name: u.name, email: u.email, role: u.role, isActive: u.isActive, isEmailVerified: u.isEmailVerified }),
    };
    users.push(u);
    return u;
  };
  const byId = (id: unknown) => users.find((u) => String(u._id) === String(id));

  User.findOne = (f: Doc) => q(users.find((u) => Object.entries(f).every(([k, v]) => (typeof v === 'object' && v !== null ? true : u[k] === v))) ?? null);
  User.exists = async (f: Doc) => (users.find((u) => u.email === f.email) ? { _id: 1 } : null);
  User.findById = (id: string) => q(byId(id) ?? null);
  User.create = async (d: Doc) => makeUser({ email: d.email, password: d.password, name: d.name, verified: false });
  User.updateOne = async (f: Doc, upd: Doc) => {
    const u = byId(f._id);
    if (!u) return { matchedCount: 0 };
    const push = upd.$push?.refreshTokens;
    if (push) { u.refreshTokens.push(...push.$each); u.refreshTokens = u.refreshTokens.slice(push.$slice); }
    const pull = upd.$pull?.refreshTokens;
    if (pull?.expiresAt) u.refreshTokens = u.refreshTokens.filter((t: Doc) => !(t.expiresAt < pull.expiresAt.$lt));
    if (pull?.tokenHash) u.refreshTokens = u.refreshTokens.filter((t: Doc) => t.tokenHash !== pull.tokenHash);
    if (upd.$set) Object.assign(u, upd.$set);
    for (const [k, v] of Object.entries(upd)) if (!k.startsWith('$')) u[k] = v;
    return { matchedCount: 1 };
  };
  User.findOneAndUpdate = async (f: Doc, upd: Doc) => {
    const u = byId(f._id);
    const hash = f['refreshTokens.tokenHash'];
    if (!u || !u.refreshTokens.some((t: Doc) => t.tokenHash === hash)) return null;
    const before = { ...u, refreshTokens: [...u.refreshTokens] };
    u.refreshTokens = u.refreshTokens.filter((t: Doc) => t.tokenHash !== upd.$pull.refreshTokens.tokenHash);
    return before;
  };
  AuditLog.create = async (d: Doc) => { audits.push(d); return d; };
  AuditLog.exists = async () => null;
  AuditLog.countDocuments = async () => 0;

  return { users, audits, makeUser };
}
