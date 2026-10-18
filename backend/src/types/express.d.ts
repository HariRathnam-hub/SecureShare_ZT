import type { Role } from '../modules/user/user.model';
import type { DeviceContext, EdgeIdentity } from '../security/types';

declare global {
  namespace Express {
    interface Request {
      user?: { id: string; email: string; role: Role };
      /** Populated by Phase 3 middleware (device registration, Cloudflare Access verification). */
      trust?: { device?: DeviceContext; edge?: EdgeIdentity };
    }
  }
}
export {};
