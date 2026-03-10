import { Agent, AgentDecision } from '../../packages/shared/types/agent';
import { ScanContext } from '../../packages/shared/types/scan-context';

export class FormAnalysisAgent implements Agent {
    public name = 'FormAnalysisAgent';
    public description = 'Analyzes HTML forms for security best practices (HTTPS, CSRF, Masking).';
    public usesGemini = false;

    public async decide(context: ScanContext): Promise<AgentDecision> {
        // Scan the root and any discovered pages for forms
        const candidates = [context.target, ...context.discoveredPages];

        for (const target of candidates) {
            // Only scan HTML-like pages
            if (target.match(/\.(js|css|png|jpg|jpeg|gif|svg|woff|woff2|ttf|eot)$/i)) continue;

            const alreadyScanned = context.telemetry.some(t => t.tool === 'form_security_analysis' && t.input.target === target);
            if (!alreadyScanned) {
                return {
                    action: 'run_tool',
                    tool: 'form_security_analysis',
                    reasoning: `Analyzing security posture of forms at ${target}`,
                    input: { target }
                };
            }
        }

        return {
            action: 'delegate',
            nextAgent: 'OrchestratorAgent',
            reasoning: 'All identified pages have been analyzed for form security.'
        };
    }
}
