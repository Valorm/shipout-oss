import { Agent, AgentDecision } from '../../packages/shared/types/agent';
import { ScanContext } from '../../packages/shared/types/scan-context';
import { cliLogger } from '../engine/cli-logger';

export class ReportAgent implements Agent {
    public name = 'ReportAgent';
    public description = 'Synthesizes all findings into a clear, actionable security report.';
    public usesGemini = false;

    public async decide(context: ScanContext): Promise<AgentDecision> {
        // ReportAgent is usually the final step.
        // It doesn't run tools, it just logs the summary.

        cliLogger.logDebug('[ReportAgent] Finalizing scan report...');

        // In a more advanced version, this could write to a file or a database.
        // For now, it signals the end of the mission.

        return {
            action: 'stop',
            reasoning: 'Security mission complete. All agents have reported and findings are synthesized.'
        };
    }
}
