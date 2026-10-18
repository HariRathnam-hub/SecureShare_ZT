import bcrypt from 'bcrypt';
import { HydratedDocument, Model, Schema, model } from 'mongoose';
import { env } from '../../config/env';

export const ROLES = ['user', 'admin'] as const;
export type Role = (typeof ROLES)[number];

export interface RefreshTokenEntry {
  tokenHash: string; // SHA-256 of the refresh JWT. The raw token is never stored.
  expiresAt: Date;
  createdAt: Date;
  userAgent?: string;
  ip?: string;
}

export interface IUser {
  name: string;
  email: string;
  password: string;
  role: Role;
  isActive: boolean;
  isEmailVerified: boolean;
  emailVerificationToken?: string;
  emailVerificationExpires?: Date;
  passwordResetToken?: string;
  passwordResetExpires?: Date;
  passwordChangedAt?: Date;
  refreshTokens: RefreshTokenEntry[];
  lastLoginAt?: Date;
  createdAt: Date;
  updatedAt: Date;
}

interface IUserMethods {
  comparePassword(candidate: string): Promise<boolean>;
}

export type UserDocument = HydratedDocument<IUser, IUserMethods>;
type UserModel = Model<IUser, {}, IUserMethods>;

const refreshTokenSchema = new Schema<RefreshTokenEntry>(
  {
    tokenHash: { type: String, required: true },
    expiresAt: { type: Date, required: true },
    createdAt: { type: Date, default: Date.now },
    userAgent: { type: String, maxlength: 300 },
    ip: { type: String, maxlength: 64 },
  },
  { _id: false },
);

const userSchema = new Schema<IUser, UserModel, IUserMethods>(
  {
    name: { type: String, required: true, trim: true, minlength: 2, maxlength: 80 },
    email: { type: String, required: true, unique: true, lowercase: true, trim: true, maxlength: 254 },
    password: { type: String, required: true, select: false },
    role: { type: String, enum: ROLES, default: 'user' },
    isActive: { type: Boolean, default: true },
    isEmailVerified: { type: Boolean, default: false },
    emailVerificationToken: { type: String, select: false },
    emailVerificationExpires: { type: Date, select: false },
    passwordResetToken: { type: String, select: false },
    passwordResetExpires: { type: Date, select: false },
    passwordChangedAt: { type: Date },
    refreshTokens: { type: [refreshTokenSchema], default: [], select: false },
    lastLoginAt: { type: Date },
  },
  {
    timestamps: true,
    toJSON: {
      transform: (_doc, ret: Record<string, unknown>) => {
        ret.id = String(ret._id);
        for (const key of [
          '_id', '__v', 'password', 'refreshTokens', 'emailVerificationToken',
          'emailVerificationExpires', 'passwordResetToken', 'passwordResetExpires',
        ]) delete ret[key];
        return ret;
      },
    },
  },
);

userSchema.index({ emailVerificationToken: 1 }, { sparse: true });
userSchema.index({ passwordResetToken: 1 }, { sparse: true });

userSchema.pre('save', async function () {
  if (!this.isModified('password')) return;
  this.password = await bcrypt.hash(this.password, env.BCRYPT_ROUNDS);
  // Back-date 1s so a token issued right after this save is not rejected.
  if (!this.isNew) this.passwordChangedAt = new Date(Date.now() - 1000);
});

userSchema.methods.comparePassword = function (candidate: string) {
  return bcrypt.compare(candidate, this.password);
};

export const User = model<IUser, UserModel>('User', userSchema);
