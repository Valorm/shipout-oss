import { AgentTool, AgentContext, ToolResult } from '../types';
import { secureFetchBase } from './http-inspector';

export const AuthTesterTool: AgentTool = {
    name: 'AuthTester',
    description: 'Inspects authentication surfaces (login, register, reset) for bot protection, CSRF, and session handling patterns.',

    shouldRun: (ctx: AgentContext) => {
        const authKeywords = ['/login', '/auth', '/signin', '/register', '/signup', '/forgot-password', '/reset-password'];
        return Array.from(ctx.discoveredEndpoints).some(e =>
            authKeywords.some(kw => e.toLowerCase().includes(kw))
        );
    },

    execute: async (ctx: AgentContext, signal: AbortSignal): Promise<ToolResult> => {
        const findings: string[] = [];
        let severity: ToolResult['severity'] = 'LOW';

        const authEndpoints = Array.from(ctx.discoveredEndpoints).filter(e => {
            const low = e.toLowerCase();
            return low.includes('/login') || low.includes('/auth') || low.includes('/signin') ||
                low.includes('/register') || low.includes('/signup') ||
                low.includes('/forgot-password') || low.includes('/reset-password');
        });

        if (authEndpoints.length === 0) {
            return {
                toolName: AuthTesterTool.name,
                findings: ["No explicit auth routes discovered in context."]
            };
        }

        try {
            // Focus on the most likely login or register URL
            const primaryUrl = authEndpoints.find(e => e.includes('login') || e.includes('signin')) || authEndpoints[0];
            const res = await secureFetchBase(primaryUrl, signal, ctx);
            const html = await res.text();
            const lowerHtml = html.toLowerCase();
            const rawDataSnippet = html.substring(0, 2000);

            findings.push(`Analyzing primary auth endpoint: ${primaryUrl}`);

            // 1. Check for CSRF tokens
            const hasCsrfToken = /name=["']_?csrf["']/i.test(html) || /name=["']authenticity_token["']/i.test(html) || /"csrf-token"/i.test(html);
            if (hasCsrfToken) {
                findings.push(`Anti-CSRF protections detected.`);
            } else {
                findings.push(`No obvious Anti-CSRF tokens detected on primary auth form.`);
                severity = 'MEDIUM';
            }

            // 2. Check for Bot Protection / Captcha
            const hasCaptcha = /recaptcha|hcaptcha|turnstile|cf-turnstile|g-recaptcha/i.test(lowerHtml);
            if (hasCaptcha) {
                findings.push(`Bot protection scripts (reCAPTCHA/Turnstile) detected.`);
            } else {
                findings.push(`No native client-side bot protection scripts found.`);
            }

            // 3. Detect OAuth Providers
            const providers = [];
            if (lowerHtml.includes('google')) providers.push('Google');
            if (lowerHtml.includes('github')) providers.push('GitHub');
            if (lowerHtml.includes('facebook') || lowerHtml.includes('meta')) providers.push('Facebook');
            if (lowerHtml.includes('apple')) providers.push('Apple');
            if (lowerHtml.includes('discord')) providers.push('Discord');

            if (providers.length > 0) {
                findings.push(`Third-party OAuth providers detected: ${providers.join(', ')}.`);
            }

            // 4. Identify specific flows
            if (authEndpoints.some(e => e.includes('register') || e.includes('signup'))) {
                findings.push(`User registration flow discovered.`);
            }
            if (authEndpoints.some(e => e.includes('forgot') || e.includes('reset'))) {
                findings.push(`Password recovery flow discovered.`);
            }

            // 5. Inspect Password field types
            const hasPasswordField = /type=["']password["']/i.test(html);
            const isAutocompleteOff = /autocomplete=["'](?:off|new-password)["']/i.test(html);

            if (hasPasswordField && !isAutocompleteOff) {
                findings.push(`Password fields do not suppress autocomplete, potentially leaking credentials in shared environments.`);
            }

            return {
                toolName: AuthTesterTool.name,
                findings,
                severity,
                rawData: rawDataSnippet
            };

        } catch (e: any) {
            return {
                toolName: AuthTesterTool.name,
                findings: [`Failed to analyze auth surface: ${e.message}`],
                error: e.message
            };
        }
    }
};
