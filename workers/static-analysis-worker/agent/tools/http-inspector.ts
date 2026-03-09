import { AgentTool, AgentContext, ToolResult } from '../types';
import { validateTargetUrl } from '../../../../packages/shared/validation/ssrf-protection';
import { isRestrictedIp } from '../../../../packages/shared/security-utils/ip-utils';
import * as dns from 'dns';

async function secureFetchBase(url: string, signal: AbortSignal, ctx: AgentContext, depth = 0): Promise<Response> {
    if (depth > 5) {
        throw new Error('Too many redirects');
    }

    if (++ctx.networkCalls > 50) { // Safety check against MAX_TOTAL_REQUESTS_PER_SCAN
        throw new Error(`Exceeded maximum allowed network calls across agent session.`);
    }

    const validation = await validateTargetUrl(url);
    if (!validation.valid || !validation.hostname) {
        throw new Error(validation.error || 'Security validation failed');
    }

    let fetchUrl: string;
    const headers: Record<string, string> = {
        'User-Agent': 'Shipout-Agent/1.0',
    };

    let targetIp = validation.hostname;
    const isIp = /^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$/.test(validation.hostname) || /^[0-9a-fA-F:]+$/.test(validation.hostname);

    if (!isIp) {
        try {
            const lookupResult = await dns.promises.lookup(validation.hostname);
            targetIp = lookupResult.address;
            if (isRestrictedIp(targetIp)) {
                throw new Error(`DNS Rebinding prevented: ${validation.hostname} resolved to restricted IP ${targetIp}`);
            }
        } catch (err: any) {
            if (err.message.includes('Rebinding')) throw err;
            throw new Error(`DNS lookup failed for ${validation.hostname}`);
        }
    }

    // Pin IP to prevent rebinding during fetch
    const parsedUrl = new URL(url.startsWith('http') ? url : `https://${url}`);
    parsedUrl.hostname = targetIp.includes(':') ? `[${targetIp}]` : targetIp;
    fetchUrl = parsedUrl.toString();
    headers['Host'] = validation.hostname;

    const res = await fetch(fetchUrl, {
        method: 'GET',
        headers,
        signal,
        redirect: 'manual'
    });

    if (res.status >= 300 && res.status < 400) {
        const location = res.headers.get('location');
        if (location) {
            return secureFetchBase(new URL(location, url).toString(), signal, ctx, depth + 1);
        }
    }

    return res;
}


export const HttpInspectorTool: AgentTool = {
    name: 'HTTPInspector',
    description: 'Inspects HTTP response headers, CORS policies, cookies, and TLS behavior to identify misconfigurations.',

    shouldRun: (ctx: AgentContext) => {
        // Run on the first pass for URL targets
        return ctx.jobType === 'url';
    },

    execute: async (ctx: AgentContext, signal: AbortSignal): Promise<ToolResult> => {
        const findings: string[] = [];
        let rawData = '';
        let severity: ToolResult['severity'] = 'LOW';

        try {
            const baseUrl = ctx.target.startsWith('http') ? ctx.target : `https://${ctx.target}`;
            const res = await secureFetchBase(baseUrl, signal, ctx);

            const lowerHeaders = Object.fromEntries(
                Array.from(res.headers.entries()).map(([k, v]) => [k.toLowerCase(), v])
            );

            // 1. CORS Analysis
            const corsOrigin = lowerHeaders['access-control-allow-origin'];
            if (corsOrigin === '*') {
                findings.push('Permissive CORS configuration detected (Access-Control-Allow-Origin: *).');
                severity = 'MEDIUM';
            } else if (corsOrigin) {
                findings.push(`Restricted CORS origin detected: ${corsOrigin}.`);
            } else {
                findings.push('No CORS headers detected on main endpoint.');
            }

            // 2. Security Headers
            const requiredHeaders = ['content-security-policy', 'strict-transport-security', 'x-frame-options', 'x-content-type-options'];
            const missingHeaders = requiredHeaders.filter(h => !lowerHeaders[h]);

            if (missingHeaders.length > 0) {
                findings.push(`Missing recommended security headers: ${missingHeaders.join(', ')}.`);
            }
            if (lowerHeaders['content-security-policy']) {
                if (lowerHeaders['content-security-policy'].includes("'unsafe-inline'") || lowerHeaders['content-security-policy'].includes("'unsafe-eval'")) {
                    findings.push("Content-Security-Policy contains 'unsafe-inline' or 'unsafe-eval', weakening XSS protection.");
                    severity = 'MEDIUM';
                } else {
                    findings.push('Strict Content-Security-Policy detected.');
                }
            }

            // 3. Cookie Flags
            const setCookieHeader = res.headers.getSetCookie?.() || [];
            if (setCookieHeader.length > 0) {
                const insecureCookies = [];
                for (const cookie of setCookieHeader) {
                    if (!(/; Secure/i.test(cookie))) insecureCookies.push("Missing Secure flag");
                    if (!(/; HttpOnly/i.test(cookie))) insecureCookies.push("Missing HttpOnly flag");
                }
                if (insecureCookies.length > 0) {
                    findings.push(`Found cookies missing secure flags: ${[...new Set(insecureCookies)].join(', ')}.`);
                } else {
                    findings.push('All Set-Cookie headers contain necessary security flags.');
                }
            } else {
                findings.push('No Set-Cookie headers observed.');
            }

            // 4. Server Information Leakage
            const serverInfo = lowerHeaders['server'] || lowerHeaders['x-powered-by'];
            if (serverInfo) {
                findings.push(`Server technology leaked in headers: ${serverInfo}.`);
            }

            rawData = JSON.stringify(lowerHeaders, null, 2);

            ctx.discoveredEndpoints.add(baseUrl);

            return {
                toolName: HttpInspectorTool.name,
                findings,
                severity,
                rawData,
                suggestedNextTools: ['EndpointDiscoverer']
            };

        } catch (e: any) {
            return {
                toolName: HttpInspectorTool.name,
                findings: [`Failed to inspect HTTP headers: ${e.message}`],
                error: e.message
            };
        }
    }
};

// Export the secure fetch function for other tools to use securely
export { secureFetchBase };
