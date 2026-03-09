import { AgentTool, AgentContext, ToolResult } from '../types';
import { secureFetchBase } from './http-inspector';

export const SecretDetectionTool: AgentTool = {
    name: 'SecretDetection',
    description: 'Scans predictable files like /.env, /config.json, or /secrets.txt for exposed API keys and database credentials.',

    shouldRun: (ctx: AgentContext) => {
        return ctx.jobType === 'url';
    },

    execute: async (ctx: AgentContext, signal: AbortSignal): Promise<ToolResult> => {
        const findings: string[] = [];
        let severity: ToolResult['severity'] = 'LOW';
        const baseUrl = ctx.target.startsWith('http') ? ctx.target : `https://${ctx.target}`;

        const pathsToTest = ['/.env', '/.git/config', '/config.json', '/.aws/credentials'];

        for (const path of pathsToTest) {
            try {
                const targetUrl = new URL(path, baseUrl).toString();
                // Override fetch for this specific lightweight check to aggressively drop 404s
                const res = await secureFetchBase(targetUrl, signal, ctx);

                if (res.status === 200) {
                    const text = (await res.text()).substring(0, 10000); // cap file read

                    const secretPatterns = [
                        { name: 'Generic Secret/Key', pattern: /APP_|DB_|API_KEY|SECRET/i },
                        { name: 'Git Config', pattern: /\[core\]/ },
                        { name: 'OpenAI/Stripe', pattern: /sk_(?:live|test)_[a-zA-Z0-9]+/ },
                        { name: 'Google API Key', pattern: /AIza[0-9A-Za-z-_]{35}/ },
                        { name: 'OAuth Bearer Token', pattern: /Bearer\s+[a-zA-Z0-9._\-/=]+/i }
                    ];

                    for (const { name, pattern } of secretPatterns) {
                        if (pattern.test(text)) {
                            findings.push(`CRITICAL: Exposed ${name} detected in ${path}`);
                            severity = 'CRITICAL';
                            ctx.detectedSecrets.add(`${path} (${name})`);
                        }
                    }
                }
            } catch (e) {
                // Ignore fetch errors (e.g. 404s, connection drops) for predictable probing
            }
        }

        if (findings.length === 0) {
            findings.push("No common predictable secret files (.env, .git, etc.) were exposed.");
        }

        return {
            toolName: SecretDetectionTool.name,
            findings,
            severity
        };
    }
};
