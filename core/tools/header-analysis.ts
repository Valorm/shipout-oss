import { Tool, ToolInput, ToolOutput } from '@shared/types/tool';

export const HeaderAnalysisTool: Tool = {
    name: 'header_analysis',
    description: 'Checks target HTTP security headers (CSP, HSTS, X-Frame-Options, etc.).',

    async run(input: ToolInput, signal?: AbortSignal): Promise<ToolOutput> {
        const { target } = input;

        try {
            const response = await fetch(target, { signal, method: 'HEAD' });
            const missingHeaders = [];

            const securityHeaders = [
                'x-frame-options',
                'x-content-type-options',
                'strict-transport-security',
                'content-security-policy'
            ];

            for (const header of securityHeaders) {
                if (!response.headers.has(header)) {
                    missingHeaders.push(header);
                }
            }

            const findings = missingHeaders.map(h => `Missing critical security header: ${h}`);

            return {
                findings,
                requestsMade: 1,
                data: {
                    allHeaders: Object.fromEntries(response.headers.entries()),
                    missingCount: missingHeaders.length
                }
            };
        } catch (e: any) {
            return {
                findings: [],
                requestsMade: 1,
                error: e.message,
                data: { error: e.message }
            };
        }
    }
};
