import { Tool, ToolInput, ToolOutput } from '@shared/types/tool';

export const HttpProbeTool: Tool = {
    name: 'http_probe',
    description: 'Checks if the target is reachable, follows redirects, and gathers basic server info.',

    async run(input: ToolInput, signal?: AbortSignal): Promise<ToolOutput> {
        const { target } = input;

        try {
            const start = Date.now();
            const response = await fetch(target, { signal, method: 'HEAD' });
            const duration = Date.now() - start;

            return {
                findings: [`Target ${target} is reachable (Status: ${response.status}).`],
                requestsMade: 1,
                data: {
                    status: response.status,
                    server: response.headers.get('server') || 'unknown',
                    responseTimeMs: duration,
                    contentType: response.headers.get('content-type'),
                    redirected: response.redirected
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
