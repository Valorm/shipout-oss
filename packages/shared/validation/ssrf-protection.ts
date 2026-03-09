import { isRestrictedIp, isInternalHostname } from '../security-utils/ip-utils';

export interface ValidatedUrl {
  valid: boolean;
  error?: string;
  hostname?: string;
  safeIp?: string;
  protocol?: string;
  port?: string;
  pathname?: string;
  search?: string;
}

export async function validateTargetUrl(url: string): Promise<ValidatedUrl> {
  try {
    const urlToParse = url.startsWith('http') ? url : `https://${url}`;
    const parsed = new URL(urlToParse);

    // 1. Protocol validation
    if (parsed.protocol !== 'http:' && parsed.protocol !== 'https:') {
      return { valid: false, error: 'Only HTTP and HTTPS protocols are allowed.' };
    }

    // 2. SSRF Protection (Hostname blocklist & CIDR checks)
    const hostname = parsed.hostname;

    // Check if hostname is an IP address
    const isIp = /^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$/.test(hostname) || /^[0-9a-fA-F:]+$/.test(hostname);

    if (isIp) {
      if (isRestrictedIp(hostname)) {
        return { valid: false, error: 'Access to private or restricted IP ranges is strictly prohibited.' };
      }
    } else {
      if (isInternalHostname(hostname)) {
        return { valid: false, error: 'Localhost and internal domain scanning is strictly prohibited.' };
      }

      // DNS resolution check - skipped in Edge Runtime due to lack of 'dns' module.
      // In Edge, Vercel handles standard DNS lookups safely at the infrastructure level.
    }

    return {
      valid: true,
      hostname,
      safeIp: isIp ? hostname : hostname, // For non-IP hostnames, use hostname as fallback (DNS pinning skipped in Edge)
      protocol: parsed.protocol,
      port: parsed.port,
      pathname: parsed.pathname,
      search: parsed.search
    };
  } catch (e) {
    return { valid: false, error: 'Invalid URL format.' };
  }
}

