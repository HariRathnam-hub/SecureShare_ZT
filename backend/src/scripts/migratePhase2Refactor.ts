import 'dotenv/config';
import { connectDB, disconnectDB } from '../config/db';
import { File } from '../modules/files/file.model';
import { FileVersion } from '../modules/files/file-version.model';

/**
 * One-off, idempotent migration for databases created before the storage refactor:
 *   File.accessWindow {start,end}  ->  File.availableFrom / File.availableUntil
 *   File.r2Key / FileVersion.r2Key ->  storageKey
 * NOTE: objects that were stored in Cloudflare R2 are NOT copied to local disk.
 * If you uploaded real files while R2 was configured, export them from R2 first.
 */
(async () => {
  await connectDB();
  const w = await File.collection.updateMany({ accessWindow: { $exists: true } }, [
    { $set: { availableFrom: '$accessWindow.start', availableUntil: '$accessWindow.end' } },
    { $unset: 'accessWindow' },
  ]);
  const f = await File.collection.updateMany({ r2Key: { $exists: true } }, { $rename: { r2Key: 'storageKey' } });
  const v = await FileVersion.collection.updateMany({ r2Key: { $exists: true } }, { $rename: { r2Key: 'storageKey' } });
  console.log(`time locks migrated: ${w.modifiedCount}, files renamed: ${f.modifiedCount}, versions renamed: ${v.modifiedCount}`);
  await disconnectDB();
})().catch((e) => {
  console.error(e);
  process.exit(1);
});
