import { Agent, AgentDecision } from '@shared/types/agent';
import { ScanContext } from '@shared/types/scan-context';
import { GoogleGenerativeAI } from '@google/generative-ai';
import { extractJSON } from '@/services/agent-planner/utils';

export class VerifyAgent implements Agent {
    public name = 'VerifyAgent';
    public description = 'Verifies potential vulnerabilities to reduce false positives and increase confidence.';
    public usesGemini = true;

    private genAI: GoogleGenerativeAI;

    constructor() {
        const apiKey = process.env.GEMINI_API_KEY || '';
        this.genAI = new GoogleGenerativeAI(apiKey);
    }

    public async decide(context: ScanContext): Promise<AgentDecision> {
        // Find unverified findings
        const unverified = context.vulnerabilities.filter(f => !f.confidence || f.confidence < 0.8);

        if (unverified.length === 0) {
            return {
                action: 'delegate',
                nextAgent: 'OrchestratorAgent',
                reasoning: 'All findings have high confidence or have been verified.'
            };
        }

        const finding = unverified[0];

        // Level 5: Auto-verify obvious Informational findings
        if (finding.severity === 'INFO') {
            return {
                action: 'delegate',
                nextAgent: 'OrchestratorAgent',
                reasoning: `Confirmed informational finding: ${finding.description}`,
                updateFinding: { confidence: 1.0, verified: true }
            } as any;
        }
        const prompt = `You are a Vulnerability Verification Specialist.
Target: ${context.target}
Potential Finding: ${finding.description} (Severity: ${finding.severity})
Evidence: ${JSON.stringify(finding.evidence)}

MISSION:
Choose a tool or method to verify this finding. 
If you have enough information to confirm it, set confidence to 1.0.
If it's a false positive, explain why.

Options:
1. payload_fuzz: Use for XSS/SQLi or injection verification.
2. header_analysis: Use for security header confirmation.
3. manual_verification_instruction: Describe how a human should verify this.

Respond ONLY with valid JSON:
{
  "action": "run_tool" | "delegate",
  "tool": "payload_fuzz" | "header_analysis" | null,
  "input": { "target": "URL to test" },
  "reasoning": "How this tool confirms the specific finding.",
  "updateFinding": {
      "confidence": number,
      "verified": boolean,
      "correction": "Optional string if description needs refining"
  }
}
`;

        try {
            const model = this.genAI.getGenerativeModel({ model: 'gemini-flash-latest' });
            const result = await model.generateContent(prompt);
            const parsed = extractJSON(result.response.text());

            if (!parsed) throw new Error("Invalid JSON from VerifyAgent");

            // Heuristic for v1: If the agent provides an update, we apply it via reasoning/meta for now
            // In a fuller version, the planner would handle 'updateFinding' specifically.
            if (parsed.input && !parsed.input.target) {
                parsed.input.target = context.target;
            }

            return {
                action: parsed.action,
                tool: parsed.tool,
                input: parsed.input || { target: context.target },
                nextAgent: parsed.nextAgent || (parsed.action === 'delegate' ? 'OrchestratorAgent' : undefined),
                reasoning: `[Verification] ${parsed.reasoning}`
            };
        } catch (e: any) {
            return {
                action: 'delegate',
                nextAgent: 'OrchestratorAgent',
                reasoning: `Verification failed: ${e.message}`
            };
        }
    }
}
