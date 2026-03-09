import { Tool, ToolInput, ToolOutput } from '@shared/types/tool';

function isValidEndpoint(endpoint: string): boolean {
    const noise = ['.css', '.png', '.jpg', '.jpeg', '.svg', '.gif', '.woff', '.woff2', '.ttf', '.otf', '.js', '.map'];
    if (noise.some(ext => endpoint.toLowerCase().endsWith(ext))) return false;
    if (endpoint.length < 3) return false;
    if (endpoint.includes('http')) return false; // Focus on internal routes
    return true;
}

export const JSEndpointMinerTool: Tool = {
    name: 'js_endpoint_miner',
    description: 'Mines JavaScript files for internal routes and API endpoints using regex.',

    async run(input: ToolInput, signal?: AbortSignal): Promise<ToolOutput> {
        const { target } = input;

        try {
            const response = await fetch(target, { signal });
            if (!response.ok) {
                return { findings: [], requestsMade: 1, data: { error: `HTTP ${response.status}` } };
            }

            const text = await response.text();

            // Regex patterns for potential endpoints
            // Pattern 1: /api/...
            // Pattern 2: common routes like /login, /dashboard
            const patterns = [
                /\/api\/[a-zA-Z0-9\/_-]+/g,
                /\/v[0-9]\/[a-zA-Z0-9\/_-]+/g,
                /\/graphql/g,
                /\/gql/g,
                /wss?:\/\/[a-zA-Z0-9._\/-]+/g, // WebSockets
                /["'](\/[a-zA-Z0-9_-]{3,}(\/[a-zA-Z0-9_-]{3,})*)["']/g,
                /(?:fetch|axios|get|post|put|delete|request)\s*\(\s*["']([^"']+)["']/g,
                /(?:url|uri|path|endpoint)\s*:\s*["']([^"']+)["']/g,
                /[?&]([a-zA-Z0-9_-]+)=/g // Parameters
            ];

            const found = new Set<string>();
            for (const pattern of patterns) {
                const matches = text.matchAll(pattern);
                for (const match of matches) {
                    // match[1] if it's a capture group, otherwise match[0]
                    const endpoint = match[1] || match[0];
                    // Clean up quotes if present, and remove query parameters/fragments
                    const cleanEndpoint = endpoint.replace(/["']/g, '').split('?')[0].split('#')[0];

                    // Filter out common noise (file extensions that aren't endpoints, obvious non-routes)
                    if (isValidEndpoint(cleanEndpoint)) {
                        found.add(cleanEndpoint);
                    }
                }
            }

            const endpoints = Array.from(found);

            return {
                findings: [`Mined ${endpoints.length} potential endpoints from ${target}`],
                requestsMade: 1,
                data: {
                    endpoints,
                    source: target,
                    count: endpoints.length
                }
            };
        } catch (e: any) {
            return {
                findings: [],
                requestsMade: 1,
                data: { error: e.message }
            };
        }
    },
};
