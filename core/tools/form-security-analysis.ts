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

            // Check for HTTP forms
            const httpFormMatch = html.match(/<form[^>]+action=["']http:\/\/[^"']+["']/gi);
            if (httpFormMatch) {
                findings.push(`Insecure Form: Form submits over HTTP at ${target}`);
            }

            // Check for potential missing CSRF
            const hasForm = html.includes('<form');
            const hasCsrf = /csrf|xsrf|token/gi.test(html);
            if (hasForm && !hasCsrf) {
                findings.push(`Missing CSRF Protection: No CSRF markers found in forms at ${target}`);
            }

            // Check for unmasked password fields (type="text" for passwords)
            const badPasswordMatch = html.match(/<input[^>]+name=["']password["'][^>]+type=["']text["']/gi);
            if (badPasswordMatch) {
                findings.push(`Insecure Password Field: Password input is not masked at ${target}`);
            }

            return {
                findings,
                requestsMade: 1,
                data: {
                    formsAnalyzed: (html.match(/<form/g) || []).length,
                    threatsFound: findings.length
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
