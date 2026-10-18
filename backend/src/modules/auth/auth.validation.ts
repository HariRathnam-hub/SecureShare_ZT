import { z } from 'zod';

const email = z.string().trim().toLowerCase().email().max(254);
/** Cloudflare Turnstile token (<= 2048 chars). Optional here so dev without Turnstile keeps working; requireTurnstile() enforces it. */
const turnstileToken = z.string().max(2048).optional();

// bcrypt only uses the first 72 bytes, so cap the length.
export const passwordSchema = z
  .string()
  .min(10, 'Use at least 10 characters')
  .max(72, 'Use at most 72 characters')
  .regex(/[a-z]/, 'Add a lowercase letter')
  .regex(/[A-Z]/, 'Add an uppercase letter')
  .regex(/\d/, 'Add a number')
  .regex(/[^A-Za-z0-9]/, 'Add a symbol');

export const registerSchema = z.object({
  name: z.string().trim().min(2).max(80),
  email,
  password: passwordSchema,
  turnstileToken,
});
export const loginSchema = z.object({ email, password: z.string().min(1).max(72), turnstileToken });
export const emailOnlySchema = z.object({ email });
export const forgotPasswordSchema = emailOnlySchema.extend({ turnstileToken });
export const tokenSchema = z.object({ token: z.string().length(64).regex(/^[a-f0-9]+$/) });
export const resetPasswordSchema = tokenSchema.extend({ password: passwordSchema, turnstileToken });

// The Turnstile token is consumed by middleware and never reaches the services.
export type RegisterInput = Omit<z.infer<typeof registerSchema>, 'turnstileToken'>;
export type LoginInput = Omit<z.infer<typeof loginSchema>, 'turnstileToken'>;
