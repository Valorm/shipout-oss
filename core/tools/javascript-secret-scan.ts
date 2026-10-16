import { Tool, ToolInput, ToolOutput } from '../../packages/shared/types/tool';

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
                'Slack Token': /xox[baprs]-[0-9a-zA-Z]{10,48}/g,
                'Stripe Key': /sk_live_[0-9a-zA-Z]{24}/g,
                'Google API Key': /AIza[0-9A-Z-_]{35}/g,
                'GitHub Token': /gh[opsu]_[0-9a-zA-Z]{36}/g,
                'Firebase Key': /AIza[0-9A-Z-_]{35}/g,
                'Supabase URL': /https:\/\/[a-z0-9-]+\.supabase\.co/gi
            };

            const findings: string[] = [];
            let hasSupabase = false;
            for (const [type, regex] of Object.entries(secretsRegex)) {
                const matches = content.match(regex);
                if (matches) {
                    if (type === 'Supabase URL') {
                        hasSupabase = true;
                        findings.push(`INFO: Supabase project detected in ${target} (anon key is public by design; verify RLS policies)`);
                    } else {
                        findings.push(`Found potential ${type} in ${target}`);
                    }
                }
            }

            // A Supabase service_role key in frontend code is a critical leak:
            // it bypasses RLS entirely. Decode JWT payloads and check the role.
            if (hasSupabase) {
                const jwtRegex = /eyJ[a-zA-Z0-9_-]+\.eyJ[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+/g;
                const jwts = content.match(jwtRegex) || [];
                for (const jwt of [...new Set(jwts)]) {
                    try {
                        const payload = JSON.parse(Buffer.from(jwt.split('.')[1], 'base64').toString());
                        if (payload.role === 'service_role') {
                            findings.push(`CRITICAL: Supabase service_role key exposed in ${target}. It bypasses RLS; anyone with it has full database access.`);
                        }
                    } catch { /* not a decodable JWT */ }
                }
            }

            return {
                findings,
                requestsMade: 1,
                data: {
                    severity: findings.some(f => f.startsWith('CRITICAL')) ? 'CRITICAL' : undefined,
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
