import { AgentTool, AgentContext, ToolResult } from '../types';
import { secureFetchBase } from './http-inspector';

export const AbuseSurfaceTesterTool: AgentTool = {
    name: 'AbuseSurfaceTester',
    description: 'Detects endpoints vulnerable to mass-abuse (e.g., signup spam, email bombing, forgot password abuse).',

    shouldRun: (ctx: AgentContext) => {
        const highValueKeywords = ['/register', '/signup', '/forgot-password', '/contact', '/reset-password', '/newsletter', '/upload'];
        return Array.from(ctx.discoveredEndpoints).some(e =>
            highValueKeywords.some(kw => e.toLowerCase().includes(kw))
        );
    },

    execute: async (ctx: AgentContext, signal: AbortSignal): Promise<ToolResult> => {
        const findings: string[] = [];
        let severity: ToolResult['severity'] = 'LOW';

        const abuseEndpoints = Array.from(ctx.discoveredEndpoints).filter(e => {
            const low = e.toLowerCase();
            return low.includes('register') || low.includes('signup') ||
                low.includes('forgot') || low.includes('contact') ||
                low.includes('reset') || low.includes('upload');
        });

        for (const url of abuseEndpoints.slice(0, 3)) {
            try {
                const res = await secureFetchBase(url, signal, ctx);
                const html = await res.text();
                const lowerHtml = html.toLowerCase();

                findings.push(`Investigating abuse potential for: ${url}`);

                const hasCaptcha = /recaptcha|hcaptcha|turnstile|cf-turnstile|g-recaptcha/i.test(lowerHtml);
                if (!hasCaptcha) {
                    findings.push(`[${url}] WARNING: Missing client-side bot protection (CAPTCHA/Turnstile). Vulnerable to automated spam.`);
                    severity = 'MEDIUM';
                } else {
                    findings.push(`[${url}] Bot protection scripts detected.`);
                }

                if (url.includes('upload')) {
                    findings.push(`[${url}] INFO: File upload endpoint detected. Ensure strict MIME type validation and malware scanning.`);
                    severity = 'MEDIUM';
                }

            } catch (e: any) {
                findings.push(`Failed to analyze endpoint ${url}: ${e.message}`);
            }
        }

        if (findings.length === 0) {
            findings.push("No obvious high-value abuse surfaces discovered.");
        }

        return {
            toolName: AbuseSurfaceTesterTool.name,
            findings,
            severity
        };
    }
};
