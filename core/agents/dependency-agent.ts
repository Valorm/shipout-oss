import { Agent, AgentDecision } from '@shared/types/agent';
import { ScanContext } from '@shared/types/scan-context';

export class DependencyAgent implements Agent {
    public name = 'DependencyAgent';
    public description = 'Looks up known CVEs for package dependencies.';
    public usesGemini = false;

    public async decide(context: ScanContext): Promise<AgentDecision> {

        const hasCveLookup = context.telemetry.some(t => t.tool === 'dependency_cve_lookup');

        if (!hasCveLookup) {
            return {
                action: 'run_tool',
                tool: 'dependency_cve_lookup',
                reasoning: 'Checking project dependencies against known vulnerability databases (OSV/NVD).',
                input: { target: context.target, metadata: { targetNode: 'root' } }
            };
        }

        return {
            action: 'delegate',
            nextAgent: 'OrchestratorAgent',
            reasoning: 'Completed supply chain CVE lookups.'
        };
    }
}
