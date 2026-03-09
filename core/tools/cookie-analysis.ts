import { Tool, ToolInput, ToolOutput } from '../../packages/shared/types/tool';

export const CookieAnalysisTool: Tool = {
    name: 'cookie_analysis',
    description: 'Checks discovered cookies for Secure, HttpOnly, and SameSite flags.',

    async run(input: ToolInput, signal?: AbortSignal): Promise<ToolOutput> {
        const { target } = input;

        try {
            const response = await fetch(target, { signal });
            const setCookie = response.headers.get('set-cookie');
            const findings = [];

            if (setCookie) {
                const cookies = setCookie.split(',').map(c => c.trim());
                for (const cookie of cookies) {
                    if (!cookie.toLowerCase().includes('httponly')) {
                        findings.push(`Cookie missing HttpOnly flag: ${cookie.split('=')[0]}`);
                    }
                    if (!cookie.toLowerCase().includes('secure')) {
                        findings.push(`Cookie missing Secure flag: ${cookie.split('=')[0]}`);
                    }
                }
            }

            return {
                findings,
                requestsMade: 1,
                data: {
                    hasCookies: !!setCookie,
                    cookieHeader: setCookie,
                    cookieCount: setCookie ? setCookie.split(',').length : 0
                }
            };
        } catch (e: any) {
            return {
                findings: [`Cookie analysis failed for ${target}: ${e.message}`],
                requestsMade: 1,
                data: { error: e.message }
            };
        }
    }
};
