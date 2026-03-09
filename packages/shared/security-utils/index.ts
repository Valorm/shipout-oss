import crypto from 'crypto';

// Security utilities like token hashing, IP blocking, etc.
export function hashToken(token: string): string {
  return crypto.createHash('sha256').update(token).digest('hex');
}
