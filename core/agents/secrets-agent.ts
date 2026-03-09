import { Agent, AgentDecision } from '@shared/types/agent';
import { ScanContext } from '@shared/types/scan-context';

export class SecretsAgent implements Agent {
    public name = 'SecretsAgent';
    public description = 'Scans for exposed secrets via known regex patterns.';
    public usesGemini = false;

    public async decide(context: ScanContext): Promise<AgentDecision> {

        // Deterministic state machine
        const hasSecretScan = context.telemetry.some(t => t.tool === 'javascript_secret_scan');

        if (!hasSecretScan) {
            return {
                action: 'run_tool',
                tool: 'javascript_secret_scan',
                reasoning: 'Scanning JavaScript assets for exposed secrets and API keys.',
                input: { target: context.target, metadata: { targetNode: 'root' } }
            };
        }

        return {
            action: 'delegate',
            nextAgent: 'OrchestratorAgent',
            reasoning: 'Completed secret regex scanning.'
        };
    }
}
