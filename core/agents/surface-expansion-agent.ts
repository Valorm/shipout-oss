import { Agent, AgentDecision } from '@shared/types/agent';
import { ScanContext } from '@shared/types/scan-context';

export class SurfaceExpansionAgent implements Agent {
    public name = 'SurfaceExpansionAgent';
    public description = 'Deep discovery agent that expands the attack surface via subdomains, JS mining, and historical URLs.';
    public usesGemini = false;

    public async decide(context: ScanContext): Promise<AgentDecision> {
        // 1. Subdomain Discovery
        const hasSubdomains = context.telemetry.some(t => t.tool === 'subdomain_discovery' && t.success);
        if (!hasSubdomains) {
            return {
                action: 'run_tool',
                tool: 'subdomain_discovery',
                reasoning: 'Expanding attack surface by identifying all unique subdomains via CT logs.',
                input: { target: context.target }
            };
        }

        // 2. Historical URLs
        const hasHistorical = context.telemetry.some(t => t.tool === 'historical_discovery' && t.success);
        if (!hasHistorical) {
            return {
                action: 'run_tool',
                tool: 'historical_discovery',
                reasoning: 'Discovering legacy endpoints and historical routes from the past.',
                input: { target: context.target }
            };
        }

        // 3. JS Deep Mining (on all discovered pages)
        const jsFiles = context.discoveredPages.filter(p => p.endsWith('.js'));
        const alreadyMined = context.investigationMemory['js_endpoint_miner'] || [];
        const unminedJs = jsFiles.filter(f => !alreadyMined.includes(f));

        if (unminedJs.length > 0) {
            const nextJs = unminedJs[0];
            return {
                action: 'run_tool',
                tool: 'js_endpoint_miner',
                reasoning: `Deep mining JavaScript logic in ${nextJs} for hidden API routes.`,
                input: { target: nextJs }
            };
        }

        // 4. Parameter Fuzzing on top endpoints
        const topEndpoints = context.discoveredEndpoints.slice(0, 3);
        const alreadyFuzzed = context.investigationMemory['parameter_fuzzer'] || [];
        const unfuzzed = topEndpoints.filter(e => !alreadyFuzzed.includes(e));

        if (unfuzzed.length > 0) {
            const nextEndpoint = unfuzzed[0];
            return {
                action: 'run_tool',
                tool: 'parameter_fuzzer',
                reasoning: `Testing ${nextEndpoint} for hidden internal parameters.`,
                input: { target: nextEndpoint }
            };
        }

        return {
            action: 'delegate',
            nextAgent: 'OrchestratorAgent',
            reasoning: 'Surface expansion phase complete. Passing to security audit.'
        };
    }
}
