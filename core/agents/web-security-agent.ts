import { Agent, AgentDecision } from '@shared/types/agent';
import { ScanContext } from '@shared/types/scan-context';

export class WebSecurityAgent implements Agent {
    public name = 'WebSecurityAgent';
    public description = 'Deterministically checks headers, CORS, cookies, and rate limits.';
    public usesGemini = false;

    private step = 1;

    public async decide(context: ScanContext): Promise<AgentDecision> {
        const loginEndpoint = context.discoveredEndpoints.find(e => e.includes('login') || e.includes('auth')) || '/login';

        const hasHeader = context.telemetry.some(t => t.tool === 'header_analysis' && t.success);
        const hasCors = context.telemetry.some(t => t.tool === 'cors_test' && t.success);
        const hasCookie = context.telemetry.some(t => t.tool === 'cookie_analysis' && t.success);
        const hasRateLimit = context.telemetry.some(t => t.tool === 'rate_limit_test' && t.success);

        if (!hasHeader) {
            return {
                action: 'run_tool',
                tool: 'header_analysis',
                reasoning: 'Analyzing security headers for common misconfigurations.',
                input: { target: context.target, metadata: { targetNode: 'root' } }
            };
        }
        if (!hasCors) {
            return {
                action: 'run_tool',
                tool: 'cors_test',
                reasoning: 'Testing for permissive CORS policies.',
                input: { target: context.target, metadata: { targetNode: 'root' } }
            };
        }
        if (!hasCookie) {
            return {
                action: 'run_tool',
                tool: 'cookie_analysis',
                reasoning: 'Checking cookie security flags.',
                input: { target: context.target, metadata: { targetNode: 'root' } }
            };
        }
        if (!hasRateLimit) {
            return {
                action: 'run_tool',
                tool: 'rate_limit_test',
                reasoning: `Testing rate limits on sensitive endpoint: ${loginEndpoint}`,
                input: { target: loginEndpoint, metadata: { targetNode: `endpoint:${loginEndpoint}` } }
            };
        }

        return {
            action: 'delegate',
            nextAgent: 'OrchestratorAgent',
            reasoning: 'Web security checks complete.'
        };
    }
}
