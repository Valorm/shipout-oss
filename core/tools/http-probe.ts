import { Tool, ToolInput, ToolOutput } from '../../packages/shared/types/tool';
import { NetworkPolicyEngine } from '../../packages/shared/security-utils/network-policy-engine';

const MAX_REDIRECTS = 5;
const REDIRECT_STATUSES = new Set([301, 302, 303, 307, 308]);

export const HttpProbeTool: Tool = {
    name: 'http_probe',
    description: 'Checks if the target is reachable, follows redirects, and gathers basic server info.',

    async run(input: ToolInput, signal?: AbortSignal): Promise<ToolOutput> {
        const { target } = input;
        let requestsMade = 0;

        try {
            const start = Date.now();

            // Redirects are followed manually so that every hop target is
            // checked against the egress policy before it is requested
            // (docs/trust-boundary.md Zone E). A redirect into a restricted
            // address fails the probe instead of being followed blindly.
            let currentUrl = target;
            let redirected = false;
            let response: Response | undefined;

            for (let hop = 0; ; hop++) {
                requestsMade++;
                response = await fetch(currentUrl, { signal, method: 'HEAD', redirect: 'manual' });

                if (!REDIRECT_STATUSES.has(response.status)) break;

                const location = response.headers.get('location');
                if (!location) break;

                if (hop >= MAX_REDIRECTS) {
                    throw new Error(`Too many redirects (max ${MAX_REDIRECTS})`);
                }

                const nextUrl = new URL(location, currentUrl).toString();
                await NetworkPolicyEngine.validateEgress(nextUrl);
                currentUrl = nextUrl;
                redirected = true;
            }

            const duration = Date.now() - start;
            const finalResponse = response as Response;

            return {
                findings: [`Target ${target} is reachable (Status: ${finalResponse.status}).`],
                requestsMade,
                data: {
                    status: finalResponse.status,
                    server: finalResponse.headers.get('server') || 'unknown',
                    responseTimeMs: duration,
                    contentType: finalResponse.headers.get('content-type'),
                    redirected
                }
            };
        } catch (e: any) {
            return {
                findings: [],
                requestsMade,
                error: e.message,
                data: { error: e.message }
            };
        }
    }
};
