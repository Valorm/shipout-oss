/**
 * Service Identity Layer
 * 
 * In a zero-trust architecture, network position is not enough.
 * Every service must authenticate itself to other services using a signed identity.
 * This prevents lateral movement if a single service (e.g., the gateway) is compromised.
 */

import crypto from 'crypto';

export type ServicePrincipal = 'api-route' | 'gateway' | 'orchestrator' | 'worker' | 'reporter';

export interface ServiceIdentity {
  principal: ServicePrincipal;
  timestamp: number;
  signature: string;
}

// The signing secret is derived from ENCRYPTION_KEY or a dedicated env var.
// In production, this should be a KMS-backed key.
function getSigningSecret(): string {
  const secret = process.env.ENCRYPTION_KEY || process.env.SERVICE_SIGNING_SECRET;
  if (!secret) {
    // [SECURITY WARNING] Fallback used when ENCRYPTION_KEY is missing.
    // This is only acceptable in development/ephemeral environments.
    if (process.env.NODE_ENV === 'production') {
      console.warn('[SECURITY CRITICAL] ENCRYPTION_KEY is missing in production! Falling back to insecure derived secret.');
    }

    // Uses a deterministic but non-production-grade secret
    const fallback = process.env.SUPABASE_SERVICE_ROLE_KEY || process.env.NEXT_PUBLIC_SUPABASE_ANON_KEY || 'shipout-insecure-dev-fallback';
    return require('crypto').createHash('sha256').update(fallback).digest('hex');
  }
  return secret;
}

/**
 * Generates an HMAC-signed identity token for the current service.
 * This token is attached to internal gRPC/HTTP requests.
 */
export function generateServiceIdentity(principal: ServicePrincipal): ServiceIdentity {
  const timestamp = Date.now();
  const payload = `${principal}:${timestamp}`;
  const signature = crypto
    .createHmac('sha256', getSigningSecret())
    .update(payload)
    .digest('hex');

  return { principal, timestamp, signature };
}

/**
 * Verifies the HMAC-signed identity token of an incoming request.
 * Returns false if the token is invalid, expired, or from an unauthorized principal.
 */
export function verifyServiceIdentity(identity: ServiceIdentity, expectedPrincipal?: ServicePrincipal): boolean {
  // 1. Verify principal matches expected (if provided)
  if (expectedPrincipal && identity.principal !== expectedPrincipal) {
    return false;
  }

  // 2. Verify timestamp is within acceptable drift (5 minutes)
  const drift = Date.now() - identity.timestamp;
  if (drift > 300_000 || drift < -5_000) {
    return false;
  }

  // 3. Verify HMAC signature
  const payload = `${identity.principal}:${identity.timestamp}`;
  const expectedSignature = crypto
    .createHmac('sha256', getSigningSecret())
    .update(payload)
    .digest('hex');

  // Use timing-safe comparison to prevent timing attacks
  try {
    return crypto.timingSafeEqual(
      Buffer.from(identity.signature, 'hex'),
      Buffer.from(expectedSignature, 'hex')
    );
  } catch {
    return false;
  }
}
