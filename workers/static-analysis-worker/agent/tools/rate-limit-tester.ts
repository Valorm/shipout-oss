import { AgentTool, AgentContext, ToolResult } from '../types';
import { secureFetchBase } from './http-inspector';

export const RateLimitTesterTool: AgentTool = {
    name: 'RateLimitTester',
    description: 'Blasts an endpoint with concurrent rapid requests to determine if rate limiting is enforced.',

    shouldRun: (ctx: AgentContext) => {
        // Run if we know about APIs or logins, or explicitly asked by the AI
        return Array.from(ctx.discoveredEndpoints).some(e => e.includes('/api') || e.includes('/login') || e.includes('/auth') || e.includes('graphql'));
    },

    execute: async (ctx: AgentContext, signal: AbortSignal): Promise<ToolResult> => {
        const findings: string[] = [];
        let severity: ToolResult['severity'] = 'LOW';
        let rawData = '';

        const targetUrl = Array.from(ctx.discoveredEndpoints).find(e => e.includes('/api') || e.includes('/login')) || ctx.target;
        const testUrl = targetUrl.startsWith('http') ? targetUrl : `https://${targetUrl}`;

        const runBurst = async (count: number) => {
            const start = Date.now();
            const promises = [];
            for (let i = 0; i < count; i++) {
                promises.push(
                    secureFetchBase(testUrl, signal, ctx).then(res => ({
                        status: res.status,
                        time: Date.now() - start
                    })).catch(() => ({ status: -1, time: Date.now() - start }))
                );
            }
            return Promise.all(promises);
        };

        try {
            // Step 1: Initial Burst (5 requests)
            findings.push(`Initiating adaptive rate limit test on ${testUrl}.`);
            let results = await runBurst(5);

            const getCounts = (res: any[]) => res.reduce((acc, r) => {
                acc[r.status] = (acc[r.status] || 0) + 1;
                return acc;
            }, {} as Record<number, number>);

            let counts = getCounts(results);

            // Step 2: Adaptive escalation
            if (!counts[429] && (counts[200] || counts[401] || counts[403])) {
                findings.push(`Initial burst of 5 requests showed no throttling. Escalating to high-pressure burst (10 requests)...`);
                const secondResults = await runBurst(10);
                results = results.concat(secondResults);
                counts = getCounts(results);
            }

            const total = results.length;
            if (counts[429]) {
                findings.push(`Rate limiting detected! Received ${counts[429]} x HTTP 429 errors during total burst of ${total} requests.`);
            } else if (counts[200] === total || counts[401] === total || counts[403] === total) {
                findings.push(`CRITICAL: No rate limiting enforced on ${testUrl} after ${total} rapid requests. Endpoint is highly vulnerable to brute-force or DoS.`);
                severity = 'HIGH';
            } else if (counts[-1]) {
                findings.push(`Detected ${counts[-1]} connection drops. Likely infrastructure-level blocking (WAF/IPS) instead of application-level rate limiting.`);
                severity = 'MEDIUM';
            } else {
                findings.push(`Inconclusive results. Status distribution: ${JSON.stringify(counts)}`);
            }

            // Detect "Invisible" Throttling via timing variance
            const successfulTimes = results.filter(r => r.status >= 200 && r.status < 300).map(r => r.time);
            if (successfulTimes.length > 5) {
                const maxTime = Math.max(...successfulTimes);
                const minTime = Math.min(...successfulTimes);
                if (maxTime > minTime * 3) {
                    findings.push(`Significant response time variance detected (${minTime}ms to ${maxTime}ms). Potential 'invisible' queuing or server-side throttling active.`);
                }
            }

            return {
                toolName: RateLimitTesterTool.name,
                findings,
                severity,
                rawData: `Total requests: ${total}, Distribution: ${JSON.stringify(counts)}`
            };
        } catch (e: any) {
            return {
                toolName: RateLimitTesterTool.name,
                findings: [`Rate limit test failed: ${e.message}`],
                error: e.message
            };
        }
    }
};
