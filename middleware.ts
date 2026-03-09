import { NextResponse, type NextRequest } from 'next/server';
import { createServerClient } from '@supabase/ssr';
import { PersistentLimiter } from './services/rate-limiting/limiter';

import { EmergencyStopPolicy } from './shared/policies/emergency-stop.policy';

const MAX_PAYLOAD_SIZE = 1048576; // 1MB

const TIERED_LIMITS = {
  STRICT: { windowMs: 60_000, max: 5 },  // 5 requests per minute (for scans)
  NORMAL: { windowMs: 60_000, max: 60 } // 60 requests per minute (for metadata)
};

export async function middleware(request: NextRequest) {
  const ip = request.headers.get('x-forwarded-for')?.split(',')[0]?.trim()
    || request.headers.get('x-real-ip')
    || 'unknown';

  // 0. Emergency Stop Policy enforcement
  if (EmergencyStopPolicy.GLOBAL_SCAN_DISABLE && request.nextUrl.pathname.startsWith('/api-edge/scan') && request.method === 'POST') {
    return new NextResponse(JSON.stringify({ error: 'Maintenance: Scan engine is temporarily disabled.' }), { status: 503 });
  }

  if (EmergencyStopPolicy.BLOCKED_IPS.includes(ip)) {
    return new NextResponse(JSON.stringify({ error: 'Access Denied' }), { status: 403 });
  }

  // 2. Request Size Limit (Browser Firewall)
  const contentLength = request.headers.get('content-length');
  if (contentLength && parseInt(contentLength, 10) > MAX_PAYLOAD_SIZE) {
    return new NextResponse(JSON.stringify({ error: 'Payload Too Large' }), { status: 413 });
  }

  // Generate Nonce for CSP (Safe Hex format for Edge compatibility)
  const nonce = Array.from(crypto.getRandomValues(new Uint8Array(16)))
    .map(b => b.toString(16).padStart(2, '0'))
    .join('');

  const requestHeaders = new Headers(request.headers);
  requestHeaders.set('x-nonce', nonce);

  let response = NextResponse.next({
    request: {
      headers: requestHeaders,
    },
  });

  try {
    const supabaseUrl = process.env.NEXT_PUBLIC_SUPABASE_URL;
    const supabaseKey = process.env.NEXT_PUBLIC_SUPABASE_ANON_KEY;

    if (supabaseUrl && supabaseKey) {
      const supabase = createServerClient(supabaseUrl, supabaseKey, {
        cookies: {
          getAll() {
            return request.cookies.getAll();
          },
          setAll(cookiesToSet) {
            cookiesToSet.forEach(({ name, value }) => request.cookies.set(name, value));
            response = NextResponse.next({
              request: {
                headers: requestHeaders,
              },
            });
            cookiesToSet.forEach(({ name, value, options }) =>
              response.cookies.set(name, value, options)
            );
          },
        },
      });

      // refreshing the auth token - wrap in try to avoid crashing middleware on auth errors
      await supabase.auth.getUser().catch(err => console.error('[Middleware] Auth error:', err));
    }
  } catch (err) {
    console.error('[Middleware] Error initializing Supabase:', err);
  }

  // Rate Limiting (applied to API routes)
  if (request.nextUrl.pathname.startsWith('/api') || request.nextUrl.pathname.startsWith('/api-edge')) {
    const isScanSubmission = request.nextUrl.pathname.includes('/scan') && request.method === 'POST';
    const tier = (isScanSubmission ? 'STRICT' : 'NORMAL') as keyof typeof TIERED_LIMITS;
    const limits = TIERED_LIMITS[tier];

    try {
      // Only run rate limiting if we have the admin client/keys
      if (process.env.SUPABASE_SERVICE_ROLE_KEY) {
        const { limited, retryAfter } = await PersistentLimiter.checkLimit(ip, tier, limits.max, limits.windowMs);

        if (limited) {
          console.warn(`[Middleware] Persistent rate limit exceeded for IP: ${ip} on route: ${request.nextUrl.pathname} (Tier: ${tier})`);
          return new NextResponse(
            JSON.stringify({ error: 'Too many requests. Please slow down and try again.' }),
            { status: 429, headers: { 'Retry-After': String(retryAfter || 60) } }
          );
        }
      }
    } catch (e) {
      console.error('[Middleware] Limiter failure:', e);
    }
  }

  // 2. Security Headers Enforcement
  response.headers.set('Strict-Transport-Security', 'max-age=63072000; includeSubDomains; preload');
  response.headers.set('X-Frame-Options', 'DENY');
  response.headers.set('X-Content-Type-Options', 'nosniff');
  response.headers.set('Referrer-Policy', 'strict-origin-when-cross-origin');
  response.headers.set('Permissions-Policy', 'camera=(), microphone=(), geolocation=(), browsing-topics=()');
  response.headers.set('X-XSS-Protection', '1; mode=block');

  const isDev = process.env.NODE_ENV === 'development';
  const platformHost = process.env.NEXT_PUBLIC_PLATFORM_URL
    ? new URL(process.env.NEXT_PUBLIC_PLATFORM_URL).host
    : request.headers.get('host') || 'shipout-api.fly.dev';
  const cspScriptSrc = isDev
    ? "'self' 'unsafe-inline' 'unsafe-eval'"
    : `'self' 'nonce-${nonce}' 'strict-dynamic'`;

  // Secure CSP: Added nonce and strict-dynamic for production hardened scripts
  response.headers.set(
    'Content-Security-Policy',
    `default-src 'self'; script-src ${cspScriptSrc}; style-src 'self' 'unsafe-inline'; img-src 'self' data: https://picsum.photos https://avatars.githubusercontent.com; font-src 'self' data:; connect-src 'self' https://*.supabase.co wss://*.supabase.co https://${platformHost}; form-action 'self';`
  );

  return response;
}

export const config = {
  matcher: '/((?!_next/static|_next/image|favicon.ico).*)',
};
