import { Tool, ToolInput, ToolOutput } from '../../packages/shared/types/tool';

// Common paths that should never be publicly reachable. If the server
// answers 200 with a non-trivial body, the file is exposed.
const SENSITIVE_PATHS = [
    '/.env',
    '/.env.local',
    '/.env.production',
    '/.git/config',
    '/.git/HEAD',
    '/debug',
    '/debug/vars',
    '/server-status',
    '/phpinfo.php',
    '/.DS_Store',
    '/config.json',
    '/wp-config.php.bak',
    '/.aws/credentials',
];

const SECRET_HINTS = [
    'api_key', 'apikey', 'secret', 'password', 'passwd', 'token',
    'aws_', 'sk_live', 'sk_test', 'ghp_', 'private_key', 'database_url',
];

export const SensitiveFileProbeTool: Tool = {
    name: 'sensitive_file_probe',
    description: 'Probes common sensitive paths (/.env, /debug, /.git/config, etc.) for exposed secrets and config.',

    async run(input: ToolInput, signal?: AbortSignal): Promise<ToolOutput> {
        const { target } = input;
        const findings: string[] = [];
        const exposed: string[] = [];
        let requestsMade = 0;

        for (const p of SENSITIVE_PATHS) {
            const url = new URL(p, target).toString();
            try {
                const response = await fetch(url, { signal, redirect: 'manual' });
                requestsMade++;
                if (response.status !== 200) continue;

                const text = await response.text();
                if (text.length < 10) continue;

                const lower = text.toLowerCase();
                const looksSecret = SECRET_HINTS.some(h => lower.includes(h));

                // Only flag when the body actually looks like secrets or
                // config. A generic 200 (e.g. a catch-all homepage) is not
                // an exposed file.
                if (looksSecret) {
                    exposed.push(p);
                    findings.push(
                        `Exposed sensitive file: ${p} is publicly reachable and appears to contain secrets or config.`
                    );
                }
            } catch {
                requestsMade++;
            }
        }

        if (exposed.length === 0) {
            findings.push(`Probed ${SENSITIVE_PATHS.length} common sensitive paths. None exposed.`);
        }

        return {
            findings,
            requestsMade,
            data: {
                severity: exposed.length > 0 ? 'HIGH' : 'INFO',
                exposed,
                evidence: exposed.map(p => new URL(p, target).toString()),
            },
        };
    },
};
