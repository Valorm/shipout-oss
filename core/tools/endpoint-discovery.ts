import { Tool, ToolInput, ToolOutput } from '../../packages/shared/types/tool';

export const EndpointDiscoveryTool: Tool = {
    name: 'endpoint_discovery',
    description: 'Finds routes and endpoints by crawling the target HTML and parsing links/scripts.',

    async run(input: ToolInput, signal?: AbortSignal): Promise<ToolOutput> {
        const { target } = input;

        try {
            const response = await fetch(target, { signal });
            const html = await response.text();

            // Simple regex for link and script extraction
            const hrefRegex = /href=["']([^"']+)["']/g;
            const srcRegex = /src=["']([^"']+)["']/g;

            const hrefMatches = [...html.matchAll(hrefRegex)].map(m => m[1]);
            const srcMatches = [...html.matchAll(srcRegex)].map(m => m[1]);

            const links = [...new Set([...hrefMatches, ...srcMatches])]
                .filter(l => l.startsWith('/') || l.startsWith(target))
                .slice(0, 15); // Slightly larger limit

            return {
                findings: [`Discovered ${links.length} endpoints on ${target}`],
                requestsMade: 1,
                data: {
                    endpoints: links,
                    linksFound: links.length,
                    pageContentLength: html.length
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
