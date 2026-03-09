import { Tool, ToolInput, ToolOutput } from '../../packages/shared/types/tool';

export const SitemapAnalyzerTool: Tool = {
    name: 'sitemap_analyzer',
    description: 'Fetches and parses sitemap.xml to discover page structure and endpoints.',

    async run(input: ToolInput, signal?: AbortSignal): Promise<ToolOutput> {
        const { target } = input;
        const sitemapUrl = new URL('/sitemap.xml', target).toString();

        try {
            const response = await fetch(sitemapUrl, { signal });
            if (!response.ok) {
                return {
                    findings: [`sitemap.xml not found on ${target}`],
                    requestsMade: 1,
                    data: { status: response.status }
                };
            }

            const text = await response.text();
            const locRegex = /<loc>(https?:\/\/[^<]+)<\/loc>/g;
            const matches = [...text.matchAll(locRegex)].map(m => m[1]);

            const paths = matches.map(url => {
                try {
                    return new URL(url).pathname;
                } catch {
                    return url;
                }
            });

            return {
                findings: [`Analyzed sitemap.xml and discovered ${paths.length} page locations.`],
                requestsMade: 1,
                data: {
                    pages: [...new Set(paths)],
                    count: paths.length
                }
            };
        } catch (e: any) {
            return {
                findings: [`Failed to analyze sitemap.xml on ${target}: ${e.message}`],
                requestsMade: 1,
                data: { error: e.message }
            };
        }
    }
};
