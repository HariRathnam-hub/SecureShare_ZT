import { env } from '../config/env';
import { logger } from '../utils/logger';

const BREVO_URL = 'https://api.brevo.com/v3/smtp/email';

const escapeHtml = (s: string) =>
  s.replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' })[c]!);

interface Message {
  to: string;
  name: string;
  subject: string;
  text: string;
  html: string;
  devLink: string;
}

async function send(m: Message): Promise<void> {
  if (!env.BREVO_API_KEY || !env.EMAIL_FROM_ADDRESS) {
    // Development convenience; production validation guarantees both are set.
    logger.info(`[DEV EMAIL] ${m.subject} -> ${m.to}: ${m.devLink}`);
    return;
  }
  try {
    const res = await fetch(BREVO_URL, {
      method: 'POST',
      headers: { 'api-key': env.BREVO_API_KEY, 'content-type': 'application/json', accept: 'application/json' },
      body: JSON.stringify({
        sender: { name: env.EMAIL_FROM_NAME, email: env.EMAIL_FROM_ADDRESS },
        to: [{ email: m.to, name: m.name }],
        subject: m.subject,
        textContent: m.text,
        htmlContent: m.html,
      }),
      signal: AbortSignal.timeout(10_000),
    });
    if (!res.ok) {
      const body = (await res.text().catch(() => '')).slice(0, 300);
      logger.error('Brevo rejected email', { status: res.status, subject: m.subject, body });
    }
  } catch (err) {
    // Never fail the request (and leak account existence) because email failed.
    logger.error('Email delivery failed', { subject: m.subject, err });
  }
}

export const emailService = {
  sendVerification(to: string, name: string, token: string) {
    const link = `${env.CLIENT_URL}/verify-email?token=${token}`;
    return send({
      to, name, devLink: link,
      subject: 'Verify your SecureShare ZT email',
      text: `Hi ${name}, confirm your email: ${link}\nThis link expires in 24 hours.`,
      html: `<p>Hi ${escapeHtml(name)},</p><p><a href="${link}">Confirm your email</a>. This link expires in 24 hours.</p>`,
    });
  },
  sendPasswordReset(to: string, name: string, token: string) {
    const link = `${env.CLIENT_URL}/reset-password?token=${token}`;
    return send({
      to, name, devLink: link,
      subject: 'Reset your SecureShare ZT password',
      text: `Hi ${name}, reset your password: ${link}\nThis link expires in 1 hour. If you did not ask for this, ignore this email.`,
      html: `<p>Hi ${escapeHtml(name)},</p><p><a href="${link}">Reset your password</a>. This link expires in 1 hour. If you did not ask for this, ignore this email.</p>`,
    });
  },
};
