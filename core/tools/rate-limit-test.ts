import { Tool, ToolInput, ToolOutput } from '../../packages/shared/types/tool';

export const RateLimitTestTool: Tool = {
    name: 'rate_limit_test',
    description: 'Tests specific sensitive endpoints (like /login) for rate limiting effectiveness.',

    async run(input: ToolInput, signal?: AbortSignal): Promise<ToolOutput> {
        const { target } = input;

        const maxRequests = 5;
        let requestsMade = 0;
        let rateLimited = false;

        for (let i = 0; i < maxRequests; i++) {
            try {
                requestsMade++;
                const response = await fetch(target, { signal });
                if (response.status === 429) {
                    rateLimited = true;
                    break;
                }
            } catch (e) {
                break;
            }
        }

        return {
            findings: rateLimited ? [`Verified rate limiting at ${target}`] : [],
            requestsMade,
            data: {
                limitReached: rateLimited,
                requestsSent: requestsMade
            }
        };
    }
};
