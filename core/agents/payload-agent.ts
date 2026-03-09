import { Agent, AgentDecision } from '@shared/types/agent';
import { ScanContext } from '@shared/types/scan-context';

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
        const allEndpoints = context.discoveredEndpoints;
        const fuzzedParams = context.investigationMemory['parameter_fuzzer'] || [];

        // Sort: Endpoints with '?' or known fuzzed params come first
        const sortedEndpoints = [...allEndpoints].sort((a, b) => {
            const aHasParam = a.includes('?') || fuzzedParams.some(p => a.includes(p));
            const bHasParam = b.includes('?') || fuzzedParams.some(p => b.includes(p));
            if (aHasParam && !bHasParam) return -1;
            if (!aHasParam && bHasParam) return 1;
            return 0;
        });

        if (sortedEndpoints.length === 0) {
            return {
                action: 'delegate',
                nextAgent: 'OrchestratorAgent',
                reasoning: 'No endpoints discovered yet for payload testing.'
            };
        }

        // Find the first tool/endpoint combination that hasn't been run yet
        for (const endpoint of sortedEndpoints) {
            for (const tool of this.toolsToRun) {
                const alreadyRun = (context.investigationMemory[tool] || []).includes(endpoint);
                if (!alreadyRun) {
                    return {
                        action: 'run_tool',
                        tool: tool,
                        reasoning: `Smart Fuzzing: ${endpoint} with ${tool.replace('_', ' ')}.`,
                        input: {
                            target: endpoint,
                            contextParams: { baseUrl: context.target },
                            metadata: { targetNode: `endpoint:${endpoint}` }
                        }
                    };
                }
            }
        }

        return {
            action: 'delegate',
            nextAgent: 'OrchestratorAgent',
            reasoning: 'All prioritized endpoints have been tested with available payloads.'
        };
    }
}
