import assert from 'assert';

// Minimal env: deliberately NO R2_* variables. The app must load without them.
Object.assign(process.env, {
  NODE_ENV: 'development', MONGODB_URI: 'mongodb://localhost/x', CLIENT_URL: 'http://localhost:5173',
  JWT_ACCESS_SECRET: 'a'.repeat(40), JWT_REFRESH_SECRET: 'b'.repeat(40),
  BREVO_API_KEY: 'test-key', EMAIL_FROM_NAME: 'SecureShare ZT', EMAIL_FROM_ADDRESS: 'sender@example.com',
});

(async () => {
  const calls: { url: string; init: any }[] = [];
  (globalThis as any).fetch = async (url: string, init: any) => { calls.push({ url, init }); return { ok: true, text: async () => '' }; };

  const { emailService } = await import('../src/services/email.service');
  await emailService.sendVerification('bob@example.com', '<img src=x onerror=alert(1)>', 'f'.repeat(64));

  assert.equal(calls.length, 1);
  assert.equal(calls[0].url, 'https://api.brevo.com/v3/smtp/email');
  assert.equal(calls[0].init.headers['api-key'], 'test-key');
  const body = JSON.parse(calls[0].init.body);
  assert.deepEqual(body.sender, { name: 'SecureShare ZT', email: 'sender@example.com' });
  assert.equal(body.to[0].email, 'bob@example.com');
  assert(body.htmlContent.includes('&lt;img'), 'display name must be HTML-escaped');
  assert(!body.htmlContent.includes('<img'), 'no raw markup injected');
  assert(body.htmlContent.includes('/verify-email?token='));

  // Brevo failure must not throw (anti-enumeration: response must not depend on email success)
  (globalThis as any).fetch = async () => ({ ok: false, status: 401, text: async () => 'unauthorized' });
  await assert.doesNotReject(() => emailService.sendPasswordReset('bob@example.com', 'Bob', 'e'.repeat(64)));
  (globalThis as any).fetch = async () => { throw new Error('network down'); };
  await assert.doesNotReject(() => emailService.sendPasswordReset('bob@example.com', 'Bob', 'e'.repeat(64)));

  console.log('brevo email service: OK');
})().catch((e) => { console.error(e); process.exit(1); });
