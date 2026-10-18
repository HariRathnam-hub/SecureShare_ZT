import path from 'path';

// Control chars (incl. C1), zero-width and bidi-override characters ("invoice\u202Efdp.exe" displays as "invoiceexe.pdf").
const INVISIBLE = /[\u0000-\u001f\u007f-\u009f\u200b-\u200f\u202a-\u202e\u2060-\u2064\u2066-\u2069\ufeff]/g;
const FORBIDDEN = /[<>:"|?*\\/]/g;
const WINDOWS_RESERVED = /^(con|prn|aux|nul|com[1-9]|lpt[1-9])(\..*)?$/i;
const MAX_NAME = 120;

/**
 * Turns any string into a safe display / download filename. It is only ever used as METADATA: stored objects are keyed by
 * server-generated ids, never by this name, so it cannot influence a filesystem path. Output: no path components, no
 * control or direction-override characters, no leading dots (hidden files, ".."), no trailing dots/spaces, no Windows device
 * names, at most 120 characters with the extension preserved.
 */
export function sanitizeFileName(raw: string): string {
  let name = path.basename(String(raw).replace(/\\/g, '/'));
  name = name.normalize('NFC').replace(INVISIBLE, '').replace(FORBIDDEN, '');
  if (name.length > MAX_NAME) {
    const ext = path.extname(name);
    const keepExt = ext.length > 0 && ext.length <= 10 ? ext : '';
    name = name.slice(0, name.length - keepExt.length).slice(0, MAX_NAME - keepExt.length) + keepExt;
  }
  name = name.replace(/^[\s.]+/, '').replace(/[\s.]+$/, '');
  if (!name) return 'file';
  return WINDOWS_RESERVED.test(name) ? `_${name}` : name;
}

/** RFC 6266 / 5987 attachment header: ASCII fallback plus UTF-8 name, with every quote, backslash, CR/LF neutralised. */
export function attachmentDisposition(filename: string): string {
  const clean = sanitizeFileName(filename);
  const ascii = clean.replace(/[^\x20-\x7e]/g, '_').replace(/["\\%;]/g, '_');
  const encoded = encodeURIComponent(clean).replace(/['()*]/g, (c) => `%${c.charCodeAt(0).toString(16).toUpperCase()}`);
  return `attachment; filename="${ascii}"; filename*=UTF-8''${encoded}`;
}
