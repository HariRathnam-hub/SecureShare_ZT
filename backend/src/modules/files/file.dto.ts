import type { AccessDecision } from './access-policy.service';
import type { FileDocument } from './file.model';

const ref = (v: any) =>
  v && typeof v === 'object' && v.name !== undefined
    ? { id: String(v._id ?? v.id), name: v.name, email: v.email }
    : String(v?._id ?? v);

/** Explicit allow-list serialiser: storageKey and other internals can never leak. */
export function toFileDTO(file: FileDocument, access?: AccessDecision, opts: { includeShares?: boolean } = {}) {
  return {
    id: file.id as string,
    fileName: file.fileName,
    originalName: file.originalName,
    mimeType: file.mimeType,
    size: file.size,
    sha256: file.sha256,
    currentVersion: file.currentVersion,
    classification: file.classification,
    availableFrom: file.availableFrom ?? null,
    availableUntil: file.availableUntil ?? null,
    dataRoom: file.dataRoom ? String(file.dataRoom) : null,
    owner: ref(file.owner),
    createdAt: file.createdAt,
    updatedAt: file.updatedAt,
    ...(access && {
      access: {
        isOwner: access.isOwner,
        canDownload: access.canDownload,
        requiresPurpose: access.requiresPurpose,
        reason: access.denyReason ?? null,
      },
    }),
    ...(opts.includeShares && {
      sharedWith: file.sharedWith.map((g: any) => ({
        user: ref(g.user),
        permission: g.permission,
        grantedAt: g.grantedAt,
        expiresAt: g.expiresAt ?? null,
      })),
    }),
  };
}
