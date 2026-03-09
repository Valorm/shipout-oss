import { GoogleGenerativeAI } from "@google/generative-ai";
import { ScanContext } from "../../packages/shared/types/scan-context";
import { extractJSON } from "./utils";

export interface InvestigationObjective {
    id: string;
    description: string;
    priority: 'LOW' | 'MEDIUM' | 'HIGH';
    status: 'pending' | 'active' | 'completed' | 'failed';
}

export interface InvestigationPlan {
    strategy: string;
    phase: string;
    objectives: InvestigationObjective[];
}

export class StrategyPlanner {
    private genAI: GoogleGenerativeAI;
    private currentPlan: InvestigationPlan | null = null;

    constructor() {
        const apiKey = process.env.GEMINI_API_KEY || '';
        this.genAI = new GoogleGenerativeAI(apiKey);
    }

    public async generatePlan(context: ScanContext): Promise<InvestigationPlan> {
        if (!process.env.GEMINI_API_KEY) {
            return {
                phase: 'reconnaissance',
                strategy: "Manual inspection required due to missing API key.",
                objectives: [{ id: 'recon', description: 'Basic surface mapping', priority: 'HIGH', status: 'pending' }]
            };
        }

        const prompt = `System: Security Analysis Engine
Context: ${context.target}
Current Phase: ${context.phase || 'reconnaissance'}
Surface Data:
- Distinct Pages: ${context.discoveredPages.length}
- Identified Endpoints: ${context.discoveredEndpoints.length}
- Profiled Technologies: ${context.technologies.join(', ')}

Available Analysis Modules:
- ReconAgent: Surface mapping and asset discovery.
- SurfaceExpansionAgent: Deep discovery (Subdomains, JS mining, Historical URLs, Param fuzzing).
- WebSecurityAgent: Configuration and policy analysis (Headers, CORS, Cookies).
- SecretsAgent: Scanning assets for credentials.
- DependencyAgent: Checking tech stack for known CVEs.
- PayloadAgent: Dynamic input validation and technical testing (SQLi, XSS, SSRF).
- VerifyAgent: Validating findings and confidence scoring.

Instruction:
Generate a technical analysis plan. Adhere to the standard assessment workflow:
1. reconnaissance: Initial discovery.
2. surface_mapping: Web security analysis and surface profiling.
3. vulnerability_analysis: Secrets scanning and sensitive data discovery.
4. verification: Payload testing and vulnerability verification.


Constraint:
Respond ONLY with a valid JSON object. No conversational filler, no markdown blocks, no explanations.

JSON Structure:
{
  "phase": "reconnaissance" | "surface_mapping" | "vulnerability_analysis" | "verification", 
  "strategy": "Technical approach summary.",
  "objectives": [
    { "id": "uuid", "description": "Technical goal", "priority": "HIGH" | "MEDIUM" | "LOW" }
  ]
}`;

        try {
            const model = this.genAI.getGenerativeModel({ model: 'gemini-flash-latest' });

            const result = await Promise.race([
                model.generateContent(prompt),
                new Promise<never>((_, reject) => setTimeout(() => reject(new Error('Strategy generation timed out')), 60000))
            ]);

            const response = result.response;
            const rawText = response.text();
            const parsed = extractJSON(rawText);

            if (!parsed) {
                throw new Error(`Failed to extract valid JSON from LLM response: ${rawText.substring(0, 100)}...`);
            }

            this.currentPlan = {
                phase: (parsed.phase as any) || context.phase || 'reconnaissance',
                strategy: parsed.strategy,
                objectives: (parsed.objectives || []).map((obj: any) => ({
                    ...obj,
                    status: 'pending'
                }))
            };

            return this.currentPlan;
        } catch (e) {
            console.error('[StrategyPlanner] Failed to generate plan', e);
            return {
                phase: context.phase || 'reconnaissance',
                strategy: "Default fallback strategy",
                objectives: [{ id: 'basic-scan', description: 'Run basic security checks', priority: 'HIGH', status: 'pending' }]
            };
        }
    }

    public getCurrentPlan(): InvestigationPlan | null {
        return this.currentPlan;
    }
}
