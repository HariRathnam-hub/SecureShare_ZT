import { RequestHandler } from 'express';
import multer, { MulterError } from 'multer';
import path from 'path';
import { env } from '../../config/env';
import { AppError } from '../../utils/AppError';
import { sanitizeFileName } from '../../utils/filename';
import { SYSTEM_TARGET_ID, actorFrom, auditService } from '../audit/audit.service';

const uploader = multer({
  storage: multer.memoryStorage(),
  limits: { fileSize: env.MAX_UPLOAD_MB * 1024 * 1024, files: 1, fields: 10, parts: 12 },
}).single('file');

/** Must run AFTER `authenticate` so anonymous clients can never stream bytes into memory. */
export const uploadSingle: RequestHandler = (req, res, next) =>
  uploader(req, res, (err: unknown) => {
    if (!err) return next();
    if (err instanceof MulterError) {
      const tooBig = err.code === 'LIMIT_FILE_SIZE';
      if (req.user) {
        void Promise.resolve(
          auditService.record(actorFrom(req), 'UPLOAD_REJECTED', 'system', SYSTEM_TARGET_ID, {
            reason: tooBig ? 'file_too_large' : `multipart_${err.code}`, limitMb: env.MAX_UPLOAD_MB, status: tooBig ? 413 : 400,
          }),
        ).catch(() => undefined);
      }
      return next(new AppError(tooBig ? `File exceeds ${env.MAX_UPLOAD_MB} MB` : 'Invalid upload', tooBig ? 413 : 400));
    }
    next(err);
  });

export const ALLOWED: Record<string, string[]> = {
  'application/pdf': ['pdf'],
  'image/png': ['png'],
  'image/jpeg': ['jpg', 'jpeg'],
  'image/gif': ['gif'],
  'image/webp': ['webp'],
  'text/plain': ['txt', 'md'],
  'text/csv': ['csv'],
  'application/msword': ['doc'],
  'application/vnd.openxmlformats-officedocument.wordprocessingml.document': ['docx'],
  'application/vnd.ms-excel': ['xls'],
  'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet': ['xlsx'],
  'application/vnd.ms-powerpoint': ['ppt'],
  'application/vnd.openxmlformats-officedocument.presentationml.presentation': ['pptx'],
  'application/zip': ['zip'],
};

const startsWith = (buf: Buffer, hex: string) => buf.subarray(0, hex.length / 2).toString('hex') === hex;
/** OOXML = ZIP local-file header + the package manifest + the format's own part folder (names are stored uncompressed). */
const ooxml = (partFolder: string) => (b: Buffer) => startsWith(b, '504b0304') && b.includes('[Content_Types].xml') && b.includes(partFolder);
const MAGIC: Record<string, (b: Buffer) => boolean> = {
  'application/pdf': (b) => b.subarray(0, 5).toString('latin1') === '%PDF-',
  'image/png': (b) => startsWith(b, '89504e47'),
  'image/jpeg': (b) => startsWith(b, 'ffd8ff'),
  'image/gif': (b) => b.subarray(0, 4).toString('latin1') === 'GIF8',
  'image/webp': (b) => b.subarray(0, 4).toString('latin1') === 'RIFF' && b.subarray(8, 12).toString('latin1') === 'WEBP',
  'application/zip': (b) => startsWith(b, '504b0304'),
  'application/vnd.openxmlformats-officedocument.wordprocessingml.document': ooxml('word/'),
  'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet': ooxml('xl/'),
  'application/vnd.openxmlformats-officedocument.presentationml.presentation': ooxml('ppt/'),
  'application/msword': (b) => startsWith(b, 'd0cf11e0'),
  'application/vnd.ms-excel': (b) => startsWith(b, 'd0cf11e0'),
  'application/vnd.ms-powerpoint': (b) => startsWith(b, 'd0cf11e0'),
  'text/plain': (b) => !b.subarray(0, 8000).includes(0),
  'text/csv': (b) => !b.subarray(0, 8000).includes(0),
};

export function safeName(raw: string): string {
  // multer decodes multipart filenames as latin1; recover UTF-8, then sanitise (see utils/filename.ts).
  return sanitizeFileName(Buffer.from(raw, 'latin1').toString('utf8'));
}

export const isAllowedMime = (mime: string): boolean => Object.prototype.hasOwnProperty.call(ALLOWED, mime);

export interface CheckedUpload {
  buffer: Buffer;
  mimeType: string;
  originalName: string;
  size: number;
}

/** Allow-list by type, extension and magic bytes. The client-declared type alone is never trusted. */
export function inspectUpload(file: Express.Multer.File | undefined): CheckedUpload {
  if (!file || !file.size) throw new AppError('A non-empty file is required', 400);
  const name = safeName(file.originalname);
  const ext = path.extname(name).slice(1).toLowerCase();
  const mime = file.mimetype.toLowerCase();
  // Own-property lookups only: a client-supplied type such as "constructor" must be a clean 415, not a TypeError.
  const exts = isAllowedMime(mime) ? ALLOWED[mime] : undefined;
  if (!exts || !exts.includes(ext)) throw new AppError('This file type is not allowed', 415);
  const check = Object.prototype.hasOwnProperty.call(MAGIC, mime) ? MAGIC[mime] : undefined;
  if (!check?.(file.buffer)) throw new AppError('File content does not match its type', 415);
  return { buffer: file.buffer, mimeType: mime, originalName: name, size: file.size };
}
