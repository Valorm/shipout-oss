import { Agent, AgentDecision } from '../../packages/shared/types/agent';
import { ScanContext } from '../../packages/shared/types/scan-context';

export class DataLeakAgent implements Agent {
    public name = 'DataLeakAgent';
    public description = 'Scans API responses and pages for PII, tokens, and sensitive internal data.';
    public usesGemini = false;

    public async decide(context: ScanContext): Promise<AgentDecision> {
        // Scan the root and any discovered internal API endpoints
        const candidates = [context.target, ...context.discoveredEndpoints.filter(e => e.includes('/api/'))];

        for (const target of candidates) {
            const alreadyScanned = context.telemetry.some(t => t.tool === 'data_leak_scan' && t.input.target === target);
            if (!alreadyScanned) {
                return {
                    action: 'run_tool',
                    tool: 'data_leak_scan',
                    reasoning: `Scanning for sensitive data leakage at ${target}`,
                    input: { target }
                };
            }
        }

        return {
            action: 'delegate',
            nextAgent: 'OrchestratorAgent',
            reasoning: 'All prioritized endpoints have been scanned for data leaks.'
        };
    }
}
