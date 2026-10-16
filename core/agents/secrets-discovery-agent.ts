import { Agent, AgentDecision } from '../../packages/shared/types/agent';
import { ScanContext } from '../../packages/shared/types/scan-context';

export class SecretsDiscoveryAgent implements Agent {
    public name = 'SecretsDiscoveryAgent';
    public description = 'Scans discovered assets (JS, HTML, Configs) for exposed secrets and API keys.';
    public usesGemini = false;

    public async decide(context: ScanContext): Promise<AgentDecision> {

        // Probe common sensitive paths (/.env, /debug, /.git/config, ...)
        const hasFileProbe = context.telemetry.some(t => t.tool === 'sensitive_file_probe' && t.input.target === context.target);
        if (!hasFileProbe) {
            return {
                action: 'run_tool',
                tool: 'sensitive_file_probe',
                reasoning: 'Probing common sensitive paths for exposed secrets and config.',
                input: { target: context.target, metadata: { targetNode: 'root' } }
            };
        }

        // In v1.7, we scan the root and any important discovered JS files
        const hasRootScan = context.telemetry.some(t => t.tool === 'javascript_secret_scan' && t.input.target === context.target);

        if (!hasRootScan) {
            return {
                action: 'run_tool',
                tool: 'javascript_secret_scan',
                reasoning: 'Scanning root target for hardcoded secrets.',
                input: { target: context.target, metadata: { targetNode: 'root' } }
            };
        }

        // Scan any newly discovered JS files
        for (const page of context.discoveredPages) {
            if (page.endsWith('.js')) {
                const absoluteTarget = page.startsWith('http') ? page : new URL(page, context.target).toString();
                const alreadyScanned = context.telemetry.some(t => t.tool === 'javascript_secret_scan' && t.input.target === absoluteTarget);
                if (!alreadyScanned) {
                    return {
                        action: 'run_tool',
                        tool: 'javascript_secret_scan',
                        reasoning: `Scanning discovered JavaScript file: ${page}`,
                        input: { target: absoluteTarget, metadata: { targetNode: `file:${page}` } }
                    };
                }
            }
        }

        return {
            action: 'delegate',
            nextAgent: 'OrchestratorAgent',
            reasoning: 'All identified assets have been scanned for secrets.'
        };
    }
}
