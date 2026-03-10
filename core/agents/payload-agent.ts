import { Agent, AgentDecision } from '../../packages/shared/types/agent';
import { ScanContext } from '../../packages/shared/types/scan-context';

export class PayloadAgent implements Agent {
    public name = 'PayloadAgent';
    public description = 'Actively tests discovered endpoints with attack payloads (SQLi, XSS, SSRF, etc.).';
    public usesGemini = false;

    private endpointIndex = 0;
    private toolIndex = 0;
    private readonly toolsToRun = [
        'sqli_probe',
        'xss_probe',
        'open_redirect_probe',
        'ssrf_probe',
        'path_traversal_probe',
        'payload_fuzz'
    ];

    public async decide(context: ScanContext): Promise<AgentDecision> {
        // Support parallel worker pattern: use context.target if it's set specifically for this worker
        // Otherwise pull from discoveryQueue
        const currentTarget = context.target || (context.discoveryQueue.length > 0 ? context.discoveryQueue.shift() : null);

        if (!currentTarget) {
            return {
                action: 'delegate',
                nextAgent: 'OrchestratorAgent',
                reasoning: 'No endpoints in queue for payload testing.'
            };
        }

        const fuzzedParams = context.investigationMemory['parameter_fuzzer'] || [];

        // Find the first tool that hasn't been run yet for this target
        for (const tool of this.toolsToRun) {
            const alreadyRun = (context.investigationMemory[tool] || []).includes(currentTarget);
            if (!alreadyRun) {
                return {
                    action: 'run_tool',
                    tool: tool,
                    reasoning: `Parallel Worker: Testing ${currentTarget} with ${tool.replace('_', ' ')}.`,
                    input: {
                        target: currentTarget,
                        contextParams: { baseUrl: context.target },
                        metadata: { targetNode: `endpoint:${currentTarget}` }
                    }
                };
            }
        }

        return {
            action: 'delegate',
            nextAgent: 'OrchestratorAgent',
            reasoning: `All tests complete for ${currentTarget}.`
        };
    }
}
