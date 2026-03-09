import { ScanContext, ScanBudget } from '@shared/types/scan-context';
import { AgentPlanner } from '@core/engine/planner';
import { OrchestratorAgent } from '@core/agents/orchestrator-agent';
import { ReconAgent } from '@core/agents/recon-agent';
import { WebSecurityAgent } from '@core/agents/web-security-agent';
import { SecretsAgent } from '@core/agents/secrets-agent';
import { DependencyAgent } from '@core/agents/dependency-agent';
import { PayloadAgent } from '@core/agents/payload-agent';
import { VerifyAgent } from '@core/agents/verify-agent';
import { SurfaceExpansionAgent } from '@core/agents/surface-expansion-agent';

export class ScanEngine {
    private readonly SYNTHESIZER_AGENT_NAME = 'SynthesizerAgent';
    /**
     * Main entry point to start a scan using the AI Security Investigator Agent Architecture.
     */
    public async startScan(jobId: string, target: string, jobType: 'url' | 'repo'): Promise<ScanContext> {

        // 1. Initialize Budget
        const budget: ScanBudget = {
            maxTools: 30,
            maxRequests: 200,
            maxTime: 5 * 60 * 1000 // 300 seconds (5 minutes)
        };

        // 2. Initialize the Planner
        const planner = new AgentPlanner(budget);

        // 3. Initialize Agents
        const orchestrator = new OrchestratorAgent();
        // Register Specialists
        planner.registerAgent(new ReconAgent());
        planner.registerAgent(new SurfaceExpansionAgent());
        planner.registerAgent(new WebSecurityAgent());
        planner.registerAgent(new SecretsAgent());
        planner.registerAgent(new DependencyAgent());
        planner.registerAgent(new PayloadAgent());
        planner.registerAgent(new VerifyAgent());

        // 4. Initialize Context
        const context: ScanContext = {
            jobId,
            target,
            jobType,
            state: 'initializing',
            phase: 'reconnaissance',
            toolsUsed: 0,
            requestsMade: 0,
            startTime: Date.now(),
            discoveredPages: [],
            discoveredEndpoints: [],
            headers: {},
            technologies: [],
            vulnerabilities: [],
            detectedSecrets: [],
            agentsUsed: [],
            stagnationCounter: 0,
            investigationMemory: {},
            attackGraph: { nodes: [], edges: [] },
            telemetry: []
        };

        console.log(`[ScanEngine] Starting investigation loop for job ${jobId} (Target: ${target})`);

        // 5. Run the Investigation Loop
        context.state = 'investigating';
        const finalContext = await planner.runInvestigateLoop(orchestrator, context);

        // 6. Generate final report (Orchestrator generates summary)
        if (!finalContext.agentsUsed.includes(this.SYNTHESIZER_AGENT_NAME)) {
            finalContext.agentsUsed.push(this.SYNTHESIZER_AGENT_NAME);
        }
        finalContext.state = 'reporting';
        await this.generateReport(finalContext);

        finalContext.state = 'completed';
        console.log(`[ScanEngine] Scan completed for job ${jobId}`);

        return finalContext;
    }

    private async generateReport(context: ScanContext) {
        console.log(`[ScanEngine] Generating Gemini-powered final report with ${context.vulnerabilities.length} findings.`);

        try {
            const { ReportService } = await import('@core/report-service/engine');
            const { getAdminClient } = await import('@core/database/db');
            const supabase = getAdminClient();

            // Prepare telemetry/data for Gemini analysis
            const investigationData = JSON.stringify({
                target: context.target,
                pages: context.discoveredPages,
                endpoints: context.discoveredEndpoints,
                headers: context.headers,
                vulnerabilities: context.vulnerabilities,
                timeline: context.telemetry.map(t => ({
                    tool: t.tool,
                    timestamp: t.timestamp,
                    success: t.success,
                    findings: (t.result as any)?.findings || []
                }))
            }, null, 2);

            // Generate AI-powered report
            const auditResult = await ReportService.generateReport(
                context.target,
                context.jobType,
                investigationData,
                context.detectedSecrets
            );

            // Finalize Metrics with Report usage
            if (auditResult.tokens) {
                context.totalTokens = context.totalTokens || { prompt: 0, completion: 0, total: 0 };
                context.totalTokens.prompt += auditResult.tokens.prompt;
                context.totalTokens.completion += auditResult.tokens.completion;
                context.totalTokens.total += auditResult.tokens.total;

                const reportCost = (auditResult.tokens.prompt * 0.075 / 1_000_000) + (auditResult.tokens.completion * 0.30 / 1_000_000);
                context.totalCost = (context.totalCost || 0) + reportCost;
            }

            // Create UI investigation steps from telemetry
            const steps = context.telemetry.map((t, idx) => ({
                stepIndex: idx + 1,
                timestamp: t.timestamp,
                reasoning: `Used tool ${t.tool} for analysis.`,
                toolsExecuted: [t.tool],
                keyFindings: (t.result as any)?.findings || []
            }));

            const status = (context as any).hasToolErrors ? 'PARTIAL' : 'COMPLETED';
            const statusText = (context as any).hasToolErrors
                ? 'Audit complete with some tool failures.'
                : 'Audit complete.';

            await (supabase.from('jobs') as any).update({
                status: status,
                status_text: statusText,
                progress: 100,
                score: auditResult.score,
                confidence: auditResult.confidence,
                critical_issues: auditResult.criticalIssues,
                warnings: auditResult.warnings,
                fixes: auditResult.fixes,
                risk_categories: auditResult.riskCategories,
                checklist: auditResult.checklist,
                investigation_steps: steps,
                completed_at: new Date().toISOString(),
                // Telemetry
                tokens_prompt: context.totalTokens?.prompt,
                tokens_completion: context.totalTokens?.completion,
                tokens_total: context.totalTokens?.total,
                estimated_cost: context.totalCost
            }).eq('id', context.jobId);

        } catch (e: any) {
            console.error(`[ScanEngine] Failed to generate AI report: ${e.message}`);
        }
    }
}

export const scanEngine = new ScanEngine();
