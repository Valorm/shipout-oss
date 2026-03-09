import { Tool, ToolInput, ToolOutput } from '@shared/types/tool';

export const JavascriptSecretScanTool: Tool = {
    name: 'javascript_secret_scan',
    description: 'Regex-based scanning of JS blobs for exposed API keys (AWS, Stripe, Firebase, etc.).',

    async run(input: ToolInput, signal?: AbortSignal): Promise<ToolOutput> {
        const { target } = input;

        try {
            const response = await fetch(target, { signal });
            const content = await response.text();

            const secretsRegex = {
                'Generic Secret': /(secret|password|api[_-]?key|token|auth)\s*[:=]\s*["'][^"']+["']/gi,
                'AWS Key': /AKIA[0-9A-Z]{16}/g,
                'Slack Token': /xox[baprs]-[0-9a-zA-Z]{10,48}/g
            };

            const findings: string[] = [];
            for (const [type, regex] of Object.entries(secretsRegex)) {
                const matches = content.match(regex);
                if (matches) {
                    findings.push(`Found potential ${type} in ${target}`);
                }
            }

            return {
                findings,
                requestsMade: 1,
                data: {
                    secretsFound: findings.length,
                    fileSize: content.length
                }
            };
        } catch (e: any) {
            return {
                findings: [`Failed to scan JS file ${target}: ${e.message}`],
                requestsMade: 1,
                data: { error: e.message }
            };
        }
    }
};
