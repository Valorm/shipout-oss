import { Agent, AgentDecision } from '../../packages/shared/types/agent';
import { ScanContext } from '../../packages/shared/types/scan-context';
import { GoogleGenerativeAI } from '@google/generative-ai';
import { extractJSON } from '../engine/utils';

export class OrchestratorAgent implements Agent {
    public name = 'OrchestratorAgent';
    public description = 'Plans the scan, decides which specialist to route to, and stops when coverage is sufficient.';
    public usesGemini = true;

    private genAI: GoogleGenerativeAI;

    constructor() {
        const apiKey = process.env.GEMINI_API_KEY || '';
        this.genAI = new GoogleGenerativeAI(apiKey);
    }

    public async decide(context: ScanContext): Promise<AgentDecision> {
        if (!process.env.GEMINI_API_KEY) {
            console.warn('[OrchestratorAgent] No GEMINI_API_KEY found, returning stop.');
            return { action: 'stop', reasoning: 'Missing API key' };
        }

        const isStagnant = context.stagnationCounter > 2;

        const agents = [
            'ReconAgent',
            'SurfaceExpansionAgent',
            'WebSecurityAgent',
            'SecretsDiscoveryAgent',
            'DataLeakAgent',
            'FormAnalysisAgent',
            'DependencyAgent',
            'PayloadAgent',
            'VerificationAgent',
            'ExploitSimulationAgent',
            'ReportAgent'
        ];

        const missionPlan = `
1. ReconAgent: Basic connectivity and surface mapping (Crawler, Robots, Sitemap).
2. SurfaceExpansionAgent: Deep discovery (Subdomains, JS mining, Historical URLs, Param fuzzing).
3. WebSecurityAgent: Passive security audit (Headers, CORS, Cookies).
4. SecretsDiscoveryAgent: Scanning assets for credentials (AWS, Stripe, GitHub, etc.).
5. DataLeakAgent: Detecting PII, internal IDs, and tokens in responses.
6. FormAnalysisAgent: Analyzing HTML forms for insecurity (HTTP, CSRF, Masking).
7. DependencyAgent: Checking tech stack for known CVEs.
8. PayloadAgent: Active fuzzing and injection testing (SQLi, XSS, SSRF).
9. VerificationAgent: Validating findings and confidence scoring.
10. ExploitSimulationAgent: Demonstrating impact of verified vulnerabilities.
11. ReportAgent: Final synthesis and mission wrap-up.
`;

        const coverage = `Pages: ${context.discoveredPages.length}, Endpoints: ${context.discoveredEndpoints.length}`;
        const hasProbed = context.telemetry.some(t => t.tool === 'http_probe' && t.success);
        const reconGoal = context.discoveredPages.length >= 1 && context.discoveredEndpoints.length >= 15;

        const prompt = `You are the Mission Scheduler for Shipout. 
Your role is to orchestrate the scan flow. You should be brief and action-oriented.

CURRENT STATE:
${coverage}
http_probe success: ${hasProbed}
Vulnerabilities Found: ${context.vulnerabilities.length}
Target Profile: ${JSON.stringify(context.targetProfile)}
Loop Stagnation: ${isStagnant}
Reconnaissance Goal Met: ${reconGoal}

MISSION PIPELINE:
- [RECON] -> [SURFACE_EXPANSION] -> [SECURITY_AUDIT] -> [SECRETS] -> [DATA_LEAK] -> [FORMS] -> [FUZZING] -> [VERIFICATION] -> [SIMULATION] -> [REPORT]

RULES:
1. If http_probe is false, go to ReconAgent.
2. If http_probe is true AND SurfaceExpansionAgent hasn't run, go to SurfaceExpansionAgent.
3. If SurfaceExpansionAgent has run OR no new endpoints are found, move to WebSecurityAgent.
4. If WebSecurityAgent has run, move to SecretsDiscoveryAgent.
5. If SecretsDiscoveryAgent has run, move to DataLeakAgent.
6. If DataLeakAgent has run, move to FormAnalysisAgent.
7. If FormAnalysisAgent has run, move to PayloadAgent for active testing.
8. If PayloadAgent has finished, move to VerificationAgent to confirm finding confidence.
9. If high-confidence findings exist without impact proof, move to ExploitSimulationAgent.
10. If everything is verified and simulated, or if mission ends, move to ReportAgent.
11. AVOID returning to ReconAgent if it has already been executed or if Reconnaissance Goal Met is true.
12. If Loop Stagnation is true, force transition to an agent that has NOT been heavily used yet.

Respond ONLY with JSON:
{
  "action": "delegate",
  "nextAgent": "AgentName",
  "reasoning": "Short mission-focused reason"
}
`;

        try {
            const model = this.genAI.getGenerativeModel({ model: 'gemini-flash-latest' });

            // Add safety timeout for LLM generation
            const result = await Promise.race([
                model.generateContent(prompt),
                new Promise<never>((_, reject) => setTimeout(() => reject(new Error('Orchestrator decision timed out')), 60000))
            ]);

            const response = result.response;
            const rawText = response.text();
            const parsed = extractJSON(rawText);

            if (!parsed) {
                throw new Error(`Failed to extract valid JSON from LLM response: ${rawText.substring(0, 100)}...`);
            }

            // Level 5: Stagnation & Loop Protection
            const agentHistory = context.telemetry.map(t => (t as any).agent).filter(Boolean);
            const lastAgent = context.agentsUsed[context.agentsUsed.length - 1];

            // If we are delegating to the SAME agent that just finished without finding anything new
            if (parsed.action === 'delegate' && parsed.nextAgent === lastAgent && context.stagnationCounter > 1) {
                const fallback = lastAgent === 'PayloadAgent' ? 'SecretsAgent' : 'PayloadAgent';
                parsed.reasoning = `Breaking agent loop (${lastAgent}). Forcing transition to ${fallback}. ${parsed.reasoning}`;
                parsed.nextAgent = fallback;
            }

            // Extract usage metadata
            const usage = (response as any).usageMetadata;
            const tokens = usage ? {
                prompt: usage.promptTokenCount,
                completion: usage.candidatesTokenCount,
                total: usage.totalTokenCount
            } : undefined;

            return {
                action: parsed.action,
                nextAgent: parsed.nextAgent,
                reasoning: parsed.reasoning,
                tokens
            };
        } catch (e: any) {
            // Log to debug instead of error to keep the main CLI clean
            const { cliLogger } = await import('../engine/cli-logger');
            cliLogger.logDebug(`[OrchestratorAgent] Decision failed: ${e.message}`);
            return { action: 'stop', reasoning: 'LLM failed to respond correctly.' };
        }
    }
}
