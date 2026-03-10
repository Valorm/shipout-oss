import { Tool, ToolInput, ToolOutput } from '../../packages/shared/types/tool';

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
            const patterns = [
                // API Endpoints
                /\/api\/[a-zA-Z0-9\/_-]+/g,
                /\/v[0-9]\/[a-zA-Z0-9\/_-]+/g,
                /\/rest\/[a-zA-Z0-9\/_-]+/g,
                /\/graphql/g,
                /\/gql/g,

                // SPA Routes (Path: "login", component: LoginComponent etc)
                /path\s*:\s*["']([^"']+)["']/g,
                // React Router <Route path="/..." ...>
                /path=["'](\/[^"']+)["']/g,

                // WebSocket
                /wss?:\/\/[a-zA-Z0-9._\/-]+/g,

                // Generic internal routes in strings
                /["'](\/[a-zA-Z0-9_-]{3,}(\/[a-zA-Z0-9_-]{3,})*)["']/g,

                // JS Function calls (fetch, axios, etc.)
                /(?:fetch|axios|get|post|put|delete|request)\s*\(\s*["']([^"']+)["']/g,

                // Property assignments
                /(?:url|uri|path|endpoint)\s*:\s*["']([^"']+)["']/g,

                // Parameter discovery from JS assignments or query strings
                /[?&]([a-zA-Z0-9_-]+)=/g,
                /(?:params|query|data)\s*[:=]\s*\{([^\}]+)\}/g // Basic object properties
            ];

            const found = new Set<string>();
            const paramsFound = new Set<string>();

            for (const pattern of patterns) {
                const matches = text.matchAll(pattern);
                for (const match of matches) {
                    const matchedContent = match[1] || match[0];

                    if (pattern.source.includes('[?&]')) {
                        // Extract parameter name
                        paramsFound.add(match[1]);
                        continue;
                    }

                    // Clean up quotes if present, and remove query parameters/fragments
                    const cleanEndpoint = matchedContent.replace(/["']/g, '').split('?')[0].split('#')[0];

                    if (isValidEndpoint(cleanEndpoint)) {
                        found.add(cleanEndpoint);
                    }
                }
            }

            const endpoints = Array.from(found);
            const parameters = Array.from(paramsFound);

            let findingsDescription = `Mined ${endpoints.length} potential endpoints from ${target}.`;
            if (parameters.length > 0) {
                findingsDescription += ` Discovered ${parameters.length} potential parameters.`;
            }

            return {
                findings: [findingsDescription],
                requestsMade: 1,
                data: {
                    endpoints,
                    parameters,
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
