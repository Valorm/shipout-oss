import { Tool, ToolInput, ToolOutput } from '../../packages/shared/types/tool';

export const FormSecurityAnalysisTool: Tool = {
    name: 'form_security_analysis',
    description: 'Analyzes HTML forms for HTTP submission, missing CSRF tokens, and unmasked passwords.',

    async run(input: ToolInput, signal?: AbortSignal): Promise<ToolOutput> {
        const { target } = input;

        try {
            const response = await fetch(target, { signal });
            const html = await response.text();

            const findings: string[] = [];
            const forms = html.match(/<form[\s\S]*?<\/form>/gi) || [];

            forms.forEach((form, index) => {
                const actionMatch = form.match(/action=["']([^"']+)["']/i);
                const action = actionMatch ? actionMatch[1] : '';
                const methodMatch = form.match(/method=["']([^"']+)["']/i);
                const method = methodMatch ? methodMatch[1].toUpperCase() : 'GET';

                // 1. Insecure HTTP Submission
                if (action.startsWith('http://') || (action === '' && target.startsWith('http://'))) {
                    findings.push(`HIGH: Insecure Form Submission (HTTP) in form #${index + 1} at ${target}`);
                }

                // 2. Missing CSRF Protection (heuristic)
                // Look for common CSRF token patterns in hidden inputs or meta tags
                const hasCsrfToken = /csrf|xsrf|token|_token|authenticity_token/i.test(form) ||
                    /csrf-token|xsrf-token/i.test(html); // Check meta tags too

                if (method === 'POST' && !hasCsrfToken) {
                    findings.push(`MEDIUM: Potential Missing CSRF Protection in POST form #${index + 1} at ${target}`);
                }

                // 3. Unmasked Password Fields
                const passwordFields = form.match(/<input[^>]+type=["']text["'][^>]+name=["']password["']/gi) ||
                    form.match(/<input[^>]+name=["']password["'][^>]+type=["']text["']/gi);
                if (passwordFields) {
                    findings.push(`LOW: Unmasked Password Field in form #${index + 1} at ${target}`);
                }

                // 4. Sensitive data in GET forms
                if (method === 'GET' && /password|token|secret|key/i.test(form)) {
                    findings.push(`MEDIUM: Sensitive Data in GET Form (may leak in URLs) in form #${index + 1} at ${target}`);
                }
            });

            return {
                findings,
                requestsMade: 1,
                data: {
                    formsAnalyzed: forms.length,
                    threatsFound: findings.length,
                    target
                }
            };
        } catch (e: any) {
            return {
                findings: [`Failed to analyze forms at ${target}: ${e.message}`],
                requestsMade: 1,
                data: { error: e.message }
            };
        }
    }
};
