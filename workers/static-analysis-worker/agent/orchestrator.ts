import { GoogleGenerativeAI } from "@google/generative-ai";
import { AgentContext, AgentConfig, InvestigationStep, ToolResult, InvestigationReport } from './types';
import { toolRegistry } from './tool-registry';
import { WorkerLimitsPolicy } from '../limits.policy';
import { AgentLimitsPolicy } from '../../../packages/shared/policies/agent-limits.policy';
import { ReportService } from '../../../services/report-service/engine';
import { sanitizeObject } from '../../../packages/shared/security-utils/sanitization';

export class AgentOrchestrator {
    private config: AgentConfig;
    private genAI: GoogleGenerativeAI | null;

    constructor(configOverride?: Partial<AgentConfig>) {
        this.config = {
            maxSteps: AgentLimitsPolicy.MAX_INVESTIGATION_STEPS,
            maxToolsPerStep: AgentLimitsPolicy.MAX_TOOLS_PER_STEP,
            maxTotalRequests: AgentLimitsPolicy.MAX_TOTAL_REQUESTS_PER_SCAN,
            timeoutSeconds: WorkerLimitsPolicy.TIMEOUT_SECONDS,
            ...configOverride
        };

        const apiKey = process.env.GEMINI_API_KEY;
        this.genAI = apiKey ? new GoogleGenerativeAI(apiKey) : null;
    }

    public async runInvestigation(
        jobId: string,
        target: string,
        jobType: 'url' | 'repo',
        onProgress?: (progress: number, statusText: string) => Promise<void>
    ): Promise<InvestigationReport> {

        // 1. Initialize Context
        const ctx: AgentContext = {
            jobId,
            target,
            jobType,
            networkCalls: 0,
            discoveredEndpoints: new Set<string>(),
            discoveredTechnologies: new Set<string>(),
            toolResults: {},
            investigationSteps: [],
            detectedSecrets: new Set<string>(),
            startTime: Date.now(),
            isAborted: false
        };

        const controller = new AbortController();
        const timeoutId = setTimeout(() => {
            console.warn(`[Orchestrator] Hard timeout reached (${this.config.timeoutSeconds}s)`);
            ctx.isAborted = true;
            controller.abort();
        }, this.config.timeoutSeconds * 1000);

        try {
            await onProgress?.(5, "Initializing investigation agent...");

            // 2. Initial Observation & Tool Execution (Phase 1)
            // We always run tools that assert shouldRun() == true (e.g., initial HTTP inspector, Tech fingerprinting)
            await onProgress?.(15, "Performing initial reconnaissance...");
            await this.runApplicableTools(ctx, 'Initial Reconnaissance', controller.signal);

            if (!this.genAI) {
                console.warn("[Orchestrator] No GEMINI_API_KEY. Falling back to simple heuristic completion.");
                return this.generateFinalReport(ctx, onProgress);
            }

            // 3. The Decide -> Execute Loop
            for (let step = 2; step <= this.config.maxSteps + 1; step++) {
                if (ctx.isAborted || ctx.networkCalls >= this.config.maxTotalRequests) {
                    const reason = ctx.isAborted ? "Timeout reached" : "Request limit reached";
                    await onProgress?.(80, `Halting active investigation: ${reason}`);
                    break;
                }

                // Calculate progress roughly between 30% and 80%
                const progress = 30 + Math.floor((step / this.config.maxSteps) * 50);
                await onProgress?.(progress, `Analyzing findings to determine step ${step}...`);

                // Ask AI what to do next
                const decision = await this.decideNextActions(ctx, step);

                if (decision.toolsToRun.length === 0) {
                    await onProgress?.(progress + 5, `Investigation concluded naturally: ${decision.reasoning}`);

                    // Record final step reasoning
                    ctx.investigationSteps.push({
                        stepIndex: step,
                        timestamp: new Date().toISOString(),
                        reasoning: decision.reasoning,
                        toolsExecuted: [],
                        keyFindings: ["Investigation complete."]
                    });
                    break;
                }

                await onProgress?.(progress + 5, `Agent Action: ${decision.reasoning}`);

                // Execute the chosen tools
                const toolsExecuted: string[] = [];
                const stepFindings: string[] = [];

                for (const toolName of decision.toolsToRun.slice(0, this.config.maxToolsPerStep)) {
                    if (ctx.isAborted) break;

                    const tool = toolRegistry.getTool(toolName);
                    if (!tool) {
                        console.warn(`[Orchestrator] AI suggested unknown tool: ${toolName}`);
                        continue;
                    }

                    // Prevent infinite loops / re-running the same tool pointlessly
                    if (ctx.toolResults[toolName]) {
                        console.log(`[Orchestrator] Skipping tool ${toolName} as it already ran.`);
                        continue;
                    }

                    await onProgress?.(progress + 10, `Executing: ${toolName}...`);
                    try {
                        const result = await tool.execute(ctx, controller.signal);
                        ctx.toolResults[toolName] = result;
                        toolsExecuted.push(toolName);
                        if (result.findings && result.findings.length > 0) {
                            stepFindings.push(...result.findings.map(f => `[${toolName}] ${f}`));
                        }
                    } catch (e: any) {
                        console.error(`[Orchestrator] Tool ${toolName} failed:`, e);
                        const msg = `Tool failed: ${e.message}`;
                        ctx.toolResults[toolName] = { toolName, findings: [msg], error: msg };
                        stepFindings.push(`[${toolName}] Error: ${msg}`);
                    }
                }

                // Record the step
                if (toolsExecuted.length > 0 || stepFindings.length > 0) {
                    ctx.investigationSteps.push({
                        stepIndex: step,
                        timestamp: new Date().toISOString(),
                        reasoning: decision.reasoning,
                        toolsExecuted,
                        keyFindings: stepFindings.length > 0 ? stepFindings : ["No significant findings."]
                    });
                }
            }

            // 4. Analysis & Report Generation
            return await this.generateFinalReport(ctx, onProgress);

        } finally {
            clearTimeout(timeoutId);
        }
    }

    private async runApplicableTools(ctx: AgentContext, contextReasoning: string, signal: AbortSignal) {
        const applicableTools = toolRegistry.getApplicableTools(ctx);
        const toolsExecuted: string[] = [];
        const stepFindings: string[] = [];

        for (const tool of applicableTools) {
            if (ctx.isAborted || ctx.toolResults[tool.name]) continue;

            try {
                const result = await tool.execute(ctx, signal);
                ctx.toolResults[tool.name] = result;
                toolsExecuted.push(tool.name);
                if (result.findings && result.findings.length > 0) {
                    stepFindings.push(...result.findings.map(f => `[${tool.name}] ${f}`));
                }
            } catch (err: any) {
                console.error(`[Orchestrator] Default Tool ${tool.name} failed:`, err);
                ctx.toolResults[tool.name] = { toolName: tool.name, findings: [`Failed: ${err.message}`], error: err.message };
            }
        }

        if (toolsExecuted.length > 0) {
            ctx.investigationSteps.push({
                stepIndex: 1,
                timestamp: new Date().toISOString(),
                reasoning: contextReasoning,
                toolsExecuted,
                keyFindings: stepFindings.length > 0 ? stepFindings : ["Initial tools completed without major findings."]
            });
        }
    }

    private async decideNextActions(ctx: AgentContext, step: number): Promise<{ reasoning: string, toolsToRun: string[] }> {
        if (!this.genAI) return { reasoning: "No AI enabled", toolsToRun: [] };

        const availableToolsContext = toolRegistry.getToolDescriptionsForPrompt(ctx);
        if (!availableToolsContext) {
            return { reasoning: "No remaining tools available to run.", toolsToRun: [] };
        }

        const summaryContext = this.buildContextSummary(ctx);

        const prompt = `You are the decision engine for an Agentic Security Investigator inspecting a ${ctx.jobType} target: ${ctx.target}.
You are currently on investigation step ${step} of ${this.config.maxSteps}.

<GOAL>
Your goal is not just to scan the surface, but to perform a deep investigation. 
If a tool discovery reveals a sensitive path (like /login or /api/v1), you should prioritize specialized tools (AuthTester, RateLimitTester) to stress-test those specific points.
</GOAL>

<CURRENT_KNOWLEDGE>
${summaryContext}
</CURRENT_KNOWLEDGE>

<AVAILABLE_TOOLS>
${availableToolsContext}
</AVAILABLE_TOOLS>

Based on the CURRENT_KNOWLEDGE (including any previous tool ERRORS), what should the agent do next?
- If a tool failed previously, do not run it again unless you have a reason to believe it will succeed now.
- If a tool failed, consider if there is an alternative tool that can gather similar data.
- Select up to ${this.config.maxToolsPerStep} tools from the AVAILABLE_TOOLS list to run. 
- If you believe the investigation is complete or sufficient data has been gathered, return an empty array for toolsToRun.

You MUST respond with a valid JSON object ONLY:
{
  "reasoning": "A concise, single-sentence explanation of your strategy. Mention if you are pivoting due to a previous tool failure.",
  "toolsToRun": ["ToolName1", "ToolName2"] 
}`;

        try {
            const model = this.genAI.getGenerativeModel({ model: "gemini-flash-latest" });
            const result = await model.generateContent(prompt);
            const response = result.response;

            let text = response.text() || "{}";
            text = text.replace(/^```(?:json)?\s*\n?/i, '').replace(/\n?```\s*$/i, '').trim();
            const parsed = JSON.parse(text);

            return {
                reasoning: parsed.reasoning || "Proceeding with investigation.",
                toolsToRun: Array.isArray(parsed.toolsToRun) ? parsed.toolsToRun : []
            };
        } catch (e) {
            console.error(`[Orchestrator] AI decision failed:`, e);
            return { reasoning: "AI decision failed, halting loop.", toolsToRun: [] };
        }
    }

    private buildContextSummary(ctx: AgentContext): string {
        let summary = `Target: ${ctx.target}\n`;
        if (ctx.discoveredTechnologies.size > 0) {
            summary += `Detected Tech: ${Array.from(ctx.discoveredTechnologies).join(', ')}\n`;
        }
        if (ctx.discoveredEndpoints.size > 0) {
            summary += `Discovered Endpoints: ${Array.from(ctx.discoveredEndpoints).slice(0, 10).join(', ')}${ctx.discoveredEndpoints.size > 10 ? '...' : ''}\n`;
        }

        summary += `\nPast Findings:\n`;
        let hasFindings = false;
        for (const [name, result] of Object.entries(ctx.toolResults)) {
            if (result.findings?.length > 0) {
                hasFindings = true;
                summary += `[${name}]: ${result.findings.join('; ')}\n`;
            }
        }
        if (!hasFindings) summary += "No significant findings yet.\n";

        return summary;
    }

    private async generateFinalReport(ctx: AgentContext, onProgress?: (p: number, s: string) => Promise<void>): Promise<InvestigationReport> {
        await onProgress?.(90, "Synthesizing final investigation report...");

        // Construct a massive data dump for the existing ReportService engine
        // We simulate the output format that engine.ts expects from the old static worker
        const targetDataObj: any = {};
        for (const [name, result] of Object.entries(ctx.toolResults)) {
            targetDataObj[`agent_tool_${name}`] = {
                findings: result.findings,
                rawDataSnippet: result.rawData ? result.rawData.substring(0, 2000) : undefined,
                severity: result.severity,
                error: result.error
            };
        }

        // Include discovered endpoints and tech stack in the data blob
        targetDataObj['agent_context'] = {
            discoveredEndpoints: Array.from(ctx.discoveredEndpoints),
            discoveredTechnologies: Array.from(ctx.discoveredTechnologies),
            totalNetworkCalls: ctx.networkCalls,
            timeoutReached: ctx.isAborted
        };

        const stringifiedData = JSON.stringify(targetDataObj, null, 2);

        // Detect secrets are passed explicitly 
        const secretsArray = Array.from(ctx.detectedSecrets);

        // Reusing the existing robust AI engine from ReportService, but with much richer data
        const auditResult = await ReportService.generateReport(
            ctx.target,
            ctx.jobType,
            stringifiedData,
            secretsArray
        );

        return {
            ...auditResult,
            investigationSteps: ctx.investigationSteps, // Append the new agent timeline
            completedAt: new Date().toISOString()
        };
    }
}
