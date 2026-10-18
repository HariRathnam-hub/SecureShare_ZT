export class AppError extends Error {
  constructor(
    public readonly message: string,
    public readonly statusCode = 500,
    public readonly isOperational = true,
    /** Optional stable machine-readable code the frontend can branch on (e.g. APPROVAL_REQUIRED). */
    public readonly code?: string,
  ) {
    super(message);
    Object.setPrototypeOf(this, AppError.prototype);
    Error.captureStackTrace(this, this.constructor);
  }
}
