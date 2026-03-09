import crypto from 'crypto';

// Cryptographic utilities

function getEncryptionKey(): Buffer {
  const rawKey = process.env.ENCRYPTION_KEY;
  if (!rawKey) {
    throw new Error('ENCRYPTION_KEY environment variable is required');
  }
  const key = Buffer.from(rawKey, 'hex');
  if (key.length !== 32) {
    throw new Error('Invalid encryption key length. Must be 32 bytes.');
  }
  return key;
}

export function encryptData(data: string): string {
  const key = getEncryptionKey();
  const iv = crypto.randomBytes(16);
  const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);

  let encrypted = cipher.update(data, 'utf8', 'hex');
  encrypted += cipher.final('hex');
  const authTag = cipher.getAuthTag().toString('hex');

  // Return IV, auth tag, and encrypted data concatenated
  return `${iv.toString('hex')}:${authTag}:${encrypted}`;
}

export function decryptData(encryptedPayload: string): string {
  const key = getEncryptionKey();
  const parts = encryptedPayload.split(':');

  if (parts.length !== 3) {
    throw new Error('Invalid encrypted payload format. Expected iv:authTag:ciphertext');
  }

  const [ivHex, authTagHex, ciphertext] = parts;
  const iv = Buffer.from(ivHex, 'hex');
  const authTag = Buffer.from(authTagHex, 'hex');

  const decipher = crypto.createDecipheriv('aes-256-gcm', key, iv);
  decipher.setAuthTag(authTag);

  let decrypted = decipher.update(ciphertext, 'hex', 'utf8');
  decrypted += decipher.final('utf8');

  return decrypted;
}
