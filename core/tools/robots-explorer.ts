import { Tool, ToolInput, ToolOutput } from '@shared/types/tool';

export const RobotsExplorerTool: Tool = {
    name: 'robots_explorer',
    description: 'Fetches and parses robots.txt to discover hidden paths and potential targets.',

    async run(input: ToolInput, signal?: AbortSignal): Promise<ToolOutput> {
        const { target } = input;
        const robotsUrl = new URL('/robots.txt', target).toString();

        try {
            const response = await fetch(robotsUrl, { signal });
            if (!response.ok) {
                return {
                    findings: [`robots.txt not found on ${target}`],
                    requestsMade: 1,
                    data: { status: response.status }
                };
            }

            const text = await response.text();
            const lines = text.split('\n');
            const paths: string[] = [];

            lines.forEach(line => {
                const match = line.match(/^\s*(?:Allow|Disallow):\s*(\/\S*)/i);
                if (match && match[1]) {
                    paths.push(match[1]);
                }
            });

            return {
                findings: [`Analyzed robots.txt and found ${paths.length} potential paths.`],
                requestsMade: 1,
                data: {
                    paths: [...new Set(paths)],
                    content: text.substring(0, 1000)
                }
            };
        } catch (e: any) {
            return {
                findings: [],
                requestsMade: 1,
                data: { error: e.message }
            };
        }
    }
};
