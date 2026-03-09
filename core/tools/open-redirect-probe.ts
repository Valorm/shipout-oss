import { Tool, ToolInput, ToolOutput } from '@shared/types/tool';

export const OpenRedirectProbeTool: Tool = {
    name: 'open_redirect_probe',
    description: 'Tests for open redirect vulnerabilities by injecting external URLs.',

    async run(input: ToolInput, signal?: AbortSignal): Promise<ToolOutput> {
        const { target, contextParams } = input;
        const base = contextParams?.baseUrl || target;
        const payloads = [
            'https://evil.com',
            '//evil.com',
            '\/evil.com',
            'javascript:alert(1)'
        ];

        let requestsMade = 0;
        const findings: string[] = [];
        let vulnerabilityData: any = null;

        for (const payload of payloads) {
            try {
                requestsMade++;
                const baseUrlObj = new URL(target, base);
                // Common redirect parameters
                const params = ['redirect', 'url', 'next', 'dest', 'destination', 'out', 'return'];

                for (const param of params) {
                    const testUrl = new URL(baseUrlObj.toString());
                    testUrl.searchParams.set(param, payload);

                    const response = await fetch(testUrl.toString(), {
                        method: 'GET',
                        redirect: 'manual', // Important: don't follow, check the Location header
                        signal
                    });

                    const location = response.headers.get('location');
                    if (location && (location.startsWith(payload) || location.includes('evil.com'))) {
                        findings.push(`Verified Open Redirect at ${target} via parameter '${param}'`);
                        vulnerabilityData = {
                            vulnerability: 'Open Redirect',
                            payload,
                            parameter: param,
                            evidence: `Response redirected to restricted URL: ${location}`,
                            remediation: "Implement a safelist for redirect destinations or use indirect references."
                        };
                        break;
                    }
                }
                if (findings.length > 0) break;
            } catch (e: any) {
                console.warn(`[OpenRedirectProbe] Request failed: ${e.message}`);
            }
        }

        return { findings, requestsMade, data: vulnerabilityData || { status: 'clean' } };
    }
};
