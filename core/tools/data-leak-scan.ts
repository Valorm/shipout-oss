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
                'Email Address': /[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}/g,
                'Internal ID': /(?:user_id|account_id|internal_id|uid|id)["']?\s*[:=]\s*["']?([0-9a-fA-F-]{8,36}|[0-9]{5,})["']?/gi,
                'Auth Token': /(?:Bearer|Token|auth|access_token|session_id)\s*[:=]?\s*["']?([0-9a-zA-Z._-]{32,})["']?/gi,
                'JWT Token': /eyJ[a-zA-Z0-9_-]{10,}\.eyJ[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}/g,
                'API Key': /(?:api_key|apikey|secret_key|app_secret|client_secret)["']?\s*[:=]\s*["']?([a-zA-Z0-9._-]{20,})["']?/gi,
                'Server Path': /(?:\/[a-zA-Z0-9._-]+){3,}/g
            };

            const findings: string[] = [];
            const leakDetails: any[] = [];

            for (const [type, regex] of Object.entries(patterns)) {
                const matches = content.match(regex);
                if (matches) {
                    const uniqueMatches = [...new Set(matches)];
                    findings.push(`MEDIUM: Potential ${type} leaked in response from ${target} (Found ${uniqueMatches.length} unique)`);
                    leakDetails.push({
                        type,
                        count: uniqueMatches.length,
                        examples: uniqueMatches.slice(0, 3)
                    });
                }
            }

            return {
                findings,
                requestsMade: 1,
                data: {
                    leaksFound: findings.length,
                    leakDetails,
                    contentType: response.headers.get('content-type'),
                    target
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
