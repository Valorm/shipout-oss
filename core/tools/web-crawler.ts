import { Tool, ToolInput, ToolOutput } from '@shared/types/tool';

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

            matches.forEach(link => {
                try {
                    const url = new URL(link, target);
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

            return {
                findings: [
                    `Discovered ${pages.length} potential pages and ${endpoints.length} other endpoints on ${target}`
                ],
                requestsMade: 1,
                data: {
                    pages: pages.slice(0, 20),
                    endpoints: endpoints.slice(0, 20),
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
