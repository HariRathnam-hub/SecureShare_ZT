import { PDFDocument, StandardFonts, degrees, rgb } from 'pdf-lib';

export interface WatermarkInfo {
  user: string;
  userId: string;
  timestamp: string;
  ip: string;
  downloadId: string;
}

const ascii = (s: string) => s.replace(/[^\x20-\x7E]/g, '?');

/**
 * Visible forensic watermark: diagonal tag + footer on every page.
 * Deters and traces leaks; it can be cropped or re-rendered by a determined
 * attacker, so it complements (not replaces) access control and auditing.
 * Throws for encrypted or malformed PDFs. Callers must fail closed.
 */
export async function watermarkPdf(input: Buffer, info: WatermarkInfo): Promise<Buffer> {
  const pdf = await PDFDocument.load(input, { ignoreEncryption: false, updateMetadata: false });
  const font = await pdf.embedFont(StandardFonts.Helvetica);
  const footer = ascii(`Downloaded by ${info.user} | ${info.timestamp} | IP ${info.ip} | ID ${info.downloadId}`);
  const diagonal = ascii(`${info.user}  ${info.downloadId.slice(0, 8)}`);
  const angle = Math.PI / 4;

  for (const page of pdf.getPages()) {
    const { width, height } = page.getSize();
    page.drawText(footer, { x: 18, y: 10, size: 7, font, color: rgb(0.3, 0.3, 0.3), opacity: 0.9 });

    let size = Math.min(width, height) / 14;
    let textWidth = font.widthOfTextAtSize(diagonal, size);
    const maxWidth = Math.hypot(width, height) * 0.75;
    if (textWidth > maxWidth) {
      size *= maxWidth / textWidth;
      textWidth = maxWidth;
    }
    page.drawText(diagonal, {
      x: width / 2 - (textWidth / 2) * Math.cos(angle) + (size / 3) * Math.sin(angle),
      y: height / 2 - (textWidth / 2) * Math.sin(angle) - (size / 3) * Math.cos(angle),
      size,
      font,
      rotate: degrees(45),
      color: rgb(0.5, 0.5, 0.5),
      opacity: 0.18,
    });
  }
  return Buffer.from(await pdf.save());
}
