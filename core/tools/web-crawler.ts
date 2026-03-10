import { Tool, ToolInput, ToolOutput } from '../../packages/shared/types/tool';

export const WebCrawlerTool: Tool = {
    name: 'web_crawler',
    description: 'Crawls the target website to discover HTML pages and links. Useful for fulfilling page coverage requirements.',

    async run(input: ToolInput, signal?: AbortSignal): Promise<ToolOutput> {
        const { target } = input;
        const baseUrl = new URL(target);

        try {
            const response = await fetch(target, { signal });
            if (!response.ok) {
                throw new Error(`Failed to fetch ${target}: ${response.statusText}`);
            }

            const html = await response.text();
            const hrefRegex = /href=["']([^"']+)["']/g;
            const matches = [...html.matchAll(hrefRegex)].map(m => m[1]);

            const pages: string[] = [];
            const endpoints: string[] = [];
            const parameters: string[] = [];

            matches.forEach(link => {
                try {
                    const url = new URL(link, target);

                    // Collect parameters from URL
                    url.searchParams.forEach((_, key) => {
                        if (!parameters.includes(key)) parameters.push(key);
                    });

                    // Only crawl same-origin links
                    if (url.origin !== baseUrl.origin) return;

                    const path = url.pathname;
                    if (path.endsWith('.html') || path.endsWith('/') || !path.includes('.')) {
                        if (!pages.includes(path)) pages.push(path);
                    } else {
                        if (!endpoints.includes(path)) endpoints.push(path);
                    }
                } catch (e) {
                    // Ignore invalid URLs
                }
            });

            // Detect forms for hints
            const hasForms = html.includes('<form');
            const formCount = (html.match(/<form/g) || []).length;

            return {
                findings: [
                    `Discovered ${pages.length} potential pages, ${endpoints.length} endpoints, and ${parameters.length} parameters on ${target}`
                ],
                requestsMade: 1,
                data: {
                    pages: pages.slice(0, 50),
                    endpoints: endpoints.slice(0, 50),
                    parameters: parameters,
                    hasForms,
                    formCount,
                    baseUrl: target
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
