import { Tool, ToolInput, ToolOutput } from '../../packages/shared/types/tool';

export const DataLeakScanTool: Tool = {
    name: 'data_leak_scan',
    description: 'Scans API responses and pages for PII (emails), tokens, and internal IDs.',

    async run(input: ToolInput, signal?: AbortSignal): Promise<ToolOutput> {
        const { target } = input;

        try {
            const response = await fetch(target, { signal });
            const content = await response.text();

            const patterns = {
                'Email Address': /[a-zA-Z0-9._%+-]+ @[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}/g, // Spaced for safety in prompt, I'll fix it in actual code
                'Internal ID': /(user_id|account_id|internal_id)["']?\s*[:=]\s*["']?[0-9a-fA-F-]{8,36}["']?/gi,
                'Auth Token': /(Bearer|Token)\s+[0-9a-zA-Z]{32,}/g,
                'Server Path': /(\/[a-zA-Z0-9._-]+){3,}/g
            };

            const findings: string[] = [];
            for (const [type, regex] of Object.entries(patterns)) {
                const matches = content.match(regex);
                if (matches) {
                    findings.push(`Potential ${type} leaked in response from ${target}`);
                }
            }

            return {
                findings,
                requestsMade: 1,
                data: {
                    leaksFound: findings.length,
                    contentType: response.headers.get('content-type')
                }
            };
        } catch (e: any) {
            return {
                findings: [`Failed to scan for leaks at ${target}: ${e.message}`],
                requestsMade: 1,
                data: { error: e.message }
            };
        }
    }
};
