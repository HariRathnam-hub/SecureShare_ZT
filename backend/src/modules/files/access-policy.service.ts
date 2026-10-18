import { Types } from 'mongoose';
import { DataRoom, roomRole } from '../rooms/data-room.model';
import { Classification, FileDocument } from './file.model';

export interface AccessDecision {
  isOwner: boolean;
  canView: boolean;
  canDownload: boolean;
  /** Purpose + reason must accompany every non-owner download (confidential, restricted). */
  requiresPurpose: boolean;
  denyReason?: string;
  via: 'owner' | 'public' | 'grant' | 'room' | 'link' | 'none';
}

/** Classifications that demand a stated purpose and reason on each access. */
export const PURPOSE_REQUIRED: readonly Classification[] = ['confidential', 'restricted'];
/** Longest grant an owner may issue for a restricted file (days). */
export const RESTRICTED_MAX_GRANT_DAYS = 7;

const NONE: AccessDecision = { isOwner: false, canView: false, canDownload: false, requiresPurpose: false, via: 'none' };
const idOf = (v: Types.ObjectId | { _id: Types.ObjectId }): string => String((v as any)._id ?? v);

/** True when `userId` holds an unexpired grant that originated from an APPROVED access request (the owner's explicit decision). */
export function hasApprovedGrant(file: Pick<FileDocument, 'sharedWith'>, userId: string, now = new Date()): boolean {
  return file.sharedWith.some((g) => String(g.user) === userId && !!g.requestId && !!g.expiresAt && g.expiresAt > now);
}

/** Returns a denial message when `now` is outside the file's availability window. */
export function timeLockViolation(file: Pick<FileDocument, 'availableFrom' | 'availableUntil'>, now: Date): string | undefined {
  if (file.availableFrom && now < file.availableFrom) return 'This file is not available yet';
  if (file.availableUntil && now > file.availableUntil) return 'This file is no longer available';
  return undefined;
}

function applyTimeLock(file: FileDocument, d: AccessDecision, now: Date): AccessDecision {
  const violation = d.canDownload ? timeLockViolation(file, now) : undefined;
  return violation ? { ...d, canDownload: false, denyReason: violation } : d;
}

/**
 * Single source of truth for file authorization. Everything is derived from
 * server state (never client input) on every call.
 *
 *  public        any authenticated user
 *  internal      owner, explicit unexpired grant, or data-room member
 *  confidential  as internal, plus purpose + reason on every non-owner download
 *  restricted    owner, or a user holding an unexpired grant that came from an
 *                APPROVED ACCESS REQUEST. Direct shares, rooms and links never
 *                count. Purpose + reason required on every download.
 *
 * Time lock (availableFrom / availableUntil) blocks every non-owner download
 * outside the window. The owner is exempt so they can always manage their file.
 * The admin role grants NO content access (least privilege).
 */
export async function evaluateFileAccess(file: FileDocument, userId: string, now = new Date()): Promise<AccessDecision> {
  if (idOf(file.owner) === userId) {
    return { isOwner: true, canView: true, canDownload: true, requiresPurpose: false, via: 'owner' };
  }
  const restricted = file.classification === 'restricted';

  let level = 0; // 1 = view, 2 = download
  let via: AccessDecision['via'] = 'none';
  const raise = (l: number, v: AccessDecision['via']) => {
    if (l > level) {
      level = l;
      via = v;
    }
  };

  if (file.classification === 'public') raise(2, 'public');

  const grant = file.sharedWith.find((g) => String(g.user) === userId && (!g.expiresAt || g.expiresAt > now));
  if (grant) {
    if (!restricted) raise(grant.permission === 'download' ? 2 : 1, 'grant');
    // Restricted: only governance-approved, time-boxed grants are honoured.
    else if (grant.requestId && grant.expiresAt) raise(2, 'grant');
  }

  if (file.dataRoom && !restricted) {
    const room = await DataRoom.findById(file.dataRoom).lean();
    const role = room ? roomRole(room, userId) : null;
    if (room && role) raise(role === 'viewer' && !room.permissions.viewerCanDownload ? 1 : 2, 'room');
  }

  if (level === 0) {
    return { ...NONE, denyReason: restricted ? 'Restricted files require an approved access request' : undefined };
  }
  return applyTimeLock(
    file,
    {
      isOwner: false,
      canView: true,
      canDownload: level >= 2,
      requiresPurpose: PURPOSE_REQUIRED.includes(file.classification),
      via,
      denyReason: level >= 2 ? undefined : 'You have view-only access to this file',
    },
    now,
  );
}

/** Link redemption: the owner-issued link stands in for a per-user grant. Never valid for restricted files. */
export function evaluateLinkAccess(file: FileDocument, userId: string, now = new Date()): AccessDecision {
  if (idOf(file.owner) === userId) {
    return { isOwner: true, canView: true, canDownload: true, requiresPurpose: false, via: 'owner' };
  }
  if (file.classification === 'restricted') return { ...NONE, denyReason: 'Restricted files cannot be accessed by link' };
  return applyTimeLock(
    file,
    { isOwner: false, canView: true, canDownload: true, requiresPurpose: PURPOSE_REQUIRED.includes(file.classification), via: 'link' },
    now,
  );
}
