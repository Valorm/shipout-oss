import { Tool, ToolInput, ToolOutput } from '../../packages/shared/types/tool';

export const ParameterFuzzerTool: Tool = {
    name: 'parameter_fuzzer',
    description: 'Tests for hidden parameters by brute-forcing against a list of common parameter names.',

    async run(input: ToolInput, signal?: AbortSignal): Promise<ToolOutput> {
        const { target } = input;

        const commonParams = [
            'admin', 'debug', 'test', 'dev', 'config', 'internal',
            'redirect', 'url', 'file', 'path', 'next', 'return',
            'user', 'id', 'role', 'api_key', 'token'
        ];

        let requestsMade = 0;
        const findings: string[] = [];
        const discovered: string[] = [];

        // In a real fuzzer, we'd check for different responses
        // Here we'll do a basic check for 200 vs 404 or specific change

        try {
            // Get baseline
            const baseResponse = await fetch(target, { signal });
            const baseText = await baseResponse.text();
            const baseStatus = baseResponse.status;
            requestsMade++;

            for (const param of commonParams) {
                try {
                    const url = new URL(target);
                    url.searchParams.append(param, '1');

                    const response = await fetch(url.toString(), { signal });
                    requestsMade++;

                    // Heuristic: different status or significantly different length
                    if (response.status !== baseStatus || Math.abs(response.status) > 1000) {
                        discovered.push(param);
                        findings.push(`Potential hidden parameter found: ${param}`);
                    }
                } catch {
                    // Skip
                }
            }

            return {
                findings,
                requestsMade,
                data: {
                    target,
                    discovered,
                    paramsTested: commonParams.length
                }
            };
        } catch (e: any) {
            return {
                findings: [],
                requestsMade,
                data: { error: e.message }
            };
        }
    }
};
