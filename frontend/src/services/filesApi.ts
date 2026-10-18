import axios from 'axios';
import { api } from '../lib/api';
import type {
  AccessRequestDTO, AuditItem, Classification, FileDTO, LinkDTO, RoomDTO, RoomRole, VersionDTO,
} from '../types/api';

const d = <T>(p: Promise<{ data: { data: T } }>) => p.then((r) => r.data.data);

/** Blob responses hide JSON errors; unwrap so getErrorMessage keeps working. */
async function unwrapBlobError(err: unknown) {
  if (axios.isAxiosError(err) && err.response?.data instanceof Blob) {
    try {
      err.response.data = JSON.parse(await err.response.data.text());
    } catch { /* keep as is */ }
  }
}

/**
 * Policy-checked download. The API verifies identity, classification, purpose and
 * time lock, writes the audit record, then streams the bytes (PDFs watermarked).
 */
export async function downloadVia(endpoint: string, body: object, filename: string) {
  let blob: Blob;
  try {
    blob = (await api.post<Blob>(endpoint, body, { responseType: 'blob' })).data;
  } catch (err) {
    await unwrapBlobError(err);
    throw err;
  }
  const href = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = href;
  a.download = filename;
  document.body.appendChild(a);
  a.click();
  a.remove();
  setTimeout(() => URL.revokeObjectURL(href), 10_000);
}

export const filesApi = {
  list: (scope: 'owned' | 'shared', q?: string) =>
    d<{ files: FileDTO[]; total: number }>(api.get('/files', { params: { scope, q: q || undefined } })),
  get: (id: string) => d<{ file: FileDTO; versions: VersionDTO[] }>(api.get(`/files/${id}`)),
  upload: (form: FormData) => d<{ file: FileDTO }>(api.post('/files', form)),
  addVersion: (id: string, form: FormData) => d<{ file: FileDTO }>(api.post(`/files/${id}/versions`, form)),
  update: (id: string, body: { fileName?: string; classification?: Classification; availableFrom?: string | null; availableUntil?: string | null }) =>
    d<{ file: FileDTO }>(api.patch(`/files/${id}`, body)),
  remove: (id: string) => api.delete(`/files/${id}`),
  share: (id: string, body: { email: string; permission: 'view' | 'download'; expiresAt?: string }) => api.post(`/files/${id}/shares`, body),
  revokeShare: (id: string, userId: string) => api.delete(`/files/${id}/shares/${userId}`),
  audit: (id: string) => d<{ items: AuditItem[] }>(api.get(`/files/${id}/audit`)),
  requestAccess: (id: string, body: { purpose: string; reason: string }) => api.post(`/files/${id}/access-requests`, body),
};

export const linksApi = {
  list: () => d<{ links: LinkDTO[] }>(api.get('/links')),
  create: (fileId: string, body: { expiresInMinutes: number; maxDownloads?: number; password?: string }) =>
    d<{ token: string; link: LinkDTO }>(api.post(`/files/${fileId}/links`, body)),
  revoke: (id: string) => api.delete(`/links/${id}`),
  open: (token: string, password?: string) =>
    d<{ file: FileDTO; requiresPurpose: boolean; expiresAt: string; remainingDownloads: number | null }>(api.post('/links/open', { token, password })),
};

export const requestsApi = {
  list: (box: 'incoming' | 'outgoing') => d<{ requests: AccessRequestDTO[] }>(api.get('/access-requests', { params: { box } })),
  approve: (id: string, body: { expiresInDays: number; permission: 'view' | 'download' }) => api.post(`/access-requests/${id}/approve`, body),
  reject: (id: string) => api.post(`/access-requests/${id}/reject`, {}),
};

export const roomsApi = {
  list: () => d<{ rooms: RoomDTO[] }>(api.get('/rooms')),
  get: (id: string) => d<{ room: RoomDTO }>(api.get(`/rooms/${id}`)),
  create: (body: { name: string; description?: string }) => d<{ room: RoomDTO }>(api.post('/rooms', body)),
  update: (id: string, body: object) => api.patch(`/rooms/${id}`, body),
  remove: (id: string) => api.delete(`/rooms/${id}`),
  addMember: (id: string, body: { email: string; role: RoomRole }) => api.post(`/rooms/${id}/members`, body),
  setRole: (id: string, userId: string, role: RoomRole) => api.patch(`/rooms/${id}/members/${userId}`, { role }),
  removeMember: (id: string, userId: string) => api.delete(`/rooms/${id}/members/${userId}`),
  attachFile: (id: string, fileId: string) => api.post(`/rooms/${id}/files`, { fileId }),
  detachFile: (id: string, fileId: string) => api.delete(`/rooms/${id}/files/${fileId}`),
  audit: (id: string) => d<{ items: AuditItem[] }>(api.get(`/rooms/${id}/audit`)),
};
