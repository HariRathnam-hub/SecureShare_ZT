import 'dotenv/config';
import { connectDB, disconnectDB } from '../config/db';
import { passwordSchema } from '../modules/auth/auth.validation';
import { User } from '../modules/user/user.model';

(async () => {
  const email = process.env.ADMIN_EMAIL?.toLowerCase();
  const password = process.env.ADMIN_PASSWORD;
  if (!email || !password) throw new Error('Set ADMIN_EMAIL and ADMIN_PASSWORD');
  passwordSchema.parse(password);
  await connectDB();
  const existing = await User.findOne({ email });
  if (existing) {
    existing.role = 'admin';
    existing.isEmailVerified = true;
    await existing.save();
    console.log(`Promoted ${email} to admin`);
  } else {
    await User.create({ name: 'Administrator', email, password, role: 'admin', isEmailVerified: true });
    console.log(`Created admin ${email}`);
  }
  await disconnectDB();
})().catch((e) => {
  console.error(e);
  process.exit(1);
});
