import { Tool, ToolInput, ToolOutput } from '../../packages/shared/types/tool';

export const HistoricalDiscoveryTool: Tool = {
    name: 'historical_discovery',
    description: 'Discovers legacy and historical endpoints using Archive.org WayBack Machine.',

    async run(input: ToolInput, signal?: AbortSignal): Promise<ToolOutput> {
        let { target } = input;

        // Extract domain from URL if needed
        let domain = target;
        try {
            const url = new URL(target);
            domain = url.hostname;
        } catch {
            // Keep as is
        }

        // Wayback CDX API
        const apiUrl = `https://web.archive.org/cdx/search/cdx?url=${domain}/*&output=json&fl=original&collapse=urlkey`;

        try {
            const response = await fetch(apiUrl, { signal });
            if (!response.ok) {
                return {
                    findings: [],
                    requestsMade: 1,
                    error: `Wayback API returned ${response.status}`,
                    data: { error: `Wayback API returned ${response.status}` }
                };
            }

            const data = await response.json();
            // First row is headers
            const urls = data.slice(1).map((row: any[]) => row[0]);

            return {
                findings: [`Discovered ${urls.length} historical URLs from Archive.org.`],
                requestsMade: 1,
                data: {
                    domain,
                    urls: urls.slice(0, 50), // Limit for context size
                    totalCount: urls.length
                }
            };
        } catch (e: any) {
            return {
                findings: [],
                requestsMade: 1,
                error: e.message,
                data: { error: e.message }
            };
        }
    }
};
