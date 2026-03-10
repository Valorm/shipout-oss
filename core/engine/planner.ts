import { ScanContext, ScanBudget, GraphNode, GraphEdge, Finding } from '../../packages/shared/types/scan-context';
import { Agent } from '../../packages/shared/types/agent';
import { ToolExecutor, InvestigationLogger } from './interfaces';

export class AgentPlanner {
    private budget: ScanBudget;
    private registeredAgents: Map<string, Agent> = new Map();
    private toolExecutor: ToolExecutor;
    private logger: InvestigationLogger;

    // Stability Guardrails
    private currentAgentStepCount: number = 0;
    private lastToolName: string | null = null;
    private lastTarget: string | null = null;
    private toolRepeatCount: number = 0;
    private stagnationCounter: number = 0;
    private readonly MAX_STEPS_PER_AGENT = 8;
    private readonly MAX_TOOL_REPEATS = 3;
    private readonly MAX_STAGNATION_STEPS = 5;
    private readonly MAX_TOTAL_STEPS = 40;
    private readonly MIN_TOTAL_STEPS_BEFORE_AUTO_FINALIZE = 6;
    private readonly MAX_POLICY_BLOCKS = 4;
    private totalSteps: number = 0;
    private policyBlockCounter: number = 0;
    private targetProfileLogged: boolean = false;

    constructor(budget: ScanBudget, toolExecutor: ToolExecutor, logger: InvestigationLogger) {
        this.budget = budget;
        this.toolExecutor = toolExecutor;
        this.logger = logger;
    }

    public registerAgent(agent: Agent) {
        this.registeredAgents.set(agent.name, agent);
    }

    /**
     * The Level 4 investigation loop.
     */
    public async runInvestigateLoop(
        orchestrator: Agent,
        context: ScanContext
    ): Promise<ScanContext> {
        const { StrategyPlanner } = await import('./strategy-planner');
        const strategyPlanner = new StrategyPlanner();

        context.state = 'investigating';

        this.updateAttackGraph(context, {
            id: 'root',
            type: 'target',
            label: context.target
        });

        let currentAgent = orchestrator;
        let currentPlan: any | null = null; // InvestigationPlan type likely in strategy-planner

        while (true) {
            if (this.isBudgetExhausted(context)) {
                this.logger.logDebug(`Overall budget exhausted for job ${context.jobId}`);
                context.state = 'analyzing';
                break;
            }

            const completion = this.evaluateInvestigationCompletion(context);
            if (completion.complete && this.totalSteps >= this.MIN_TOTAL_STEPS_BEFORE_AUTO_FINALIZE) {
                this.logger.logDebug(`Auto-finalizing investigation: ${completion.reason}`);
                context.state = 'analyzing';
                break;
            }

            if (this.policyBlockCounter >= this.MAX_POLICY_BLOCKS) {
                this.logger.logDebug(`Auto-finalizing after ${this.policyBlockCounter} policy blocks.`);
                context.state = 'analyzing';
                break;
            }

            const estimatedProgress = Math.min(95, Math.floor((this.totalSteps / this.MAX_TOTAL_STEPS) * 100));

            if (!currentPlan || currentPlan.objectives.every((o: any) => o.status === 'completed' || o.status === 'failed')) {
                await this.logger.updateStatus(context.jobId, `[Orchestrator] Generating new investigation strategy...`, estimatedProgress);
                currentPlan = await strategyPlanner.generatePlan(context);
                context.currentPlan = currentPlan;
                context.phase = currentPlan.phase as any;
                // cliLogger logs handled by the provided logger or removed if specifically CLI
            }

            if (currentAgent.name !== 'OrchestratorAgent' && this.currentAgentStepCount >= this.MAX_STEPS_PER_AGENT) {
                this.logger.logDebug(`Specialist ${currentAgent.name} exceeded step budget (${this.MAX_STEPS_PER_AGENT}).`);
                currentAgent = orchestrator;
                this.currentAgentStepCount = 0;
                continue;
            }

            if (this.stagnationCounter >= this.MAX_STAGNATION_STEPS) {
                this.logger.logDebug(`Stagnation detected (${this.MAX_STAGNATION_STEPS} useless steps). Reverting to Orchestrator.`);
                currentAgent = orchestrator;
                this.stagnationCounter = 0;
                this.currentAgentStepCount = 0;
                continue;
            }

            await this.logger.updateStatus(context.jobId, `[${currentAgent.name}] Analyzing context and deciding next action...`, estimatedProgress);

            try {
                if (!context.agentsUsed.includes(currentAgent.name)) {
                    context.agentsUsed.push(currentAgent.name);
                }
                let decision = await currentAgent.decide(context);
                this.currentAgentStepCount++;
                this.totalSteps++;

                if (decision.tokens) {
                    context.totalTokens = context.totalTokens || { prompt: 0, completion: 0, total: 0 };
                    context.totalTokens.prompt += decision.tokens.prompt;
                    context.totalTokens.completion += decision.tokens.completion;
                    context.totalTokens.total += decision.tokens.total;

                    const cost = (decision.tokens.prompt * 0.075 / 1_000_000) + (decision.tokens.completion * 0.30 / 1_000_000);
                    context.totalCost = (context.totalCost || 0) + cost;
                }

                if (decision.action === 'stop') {
                    const coverage = this.checkCoverage(context);
                    if (!coverage.sufficient) {
                        const nextAgent = coverage.recommendedAgent || 'ReconAgent';
                        this.logger.logDebug(`Stop rejected. Coverage insufficient: ${coverage.reason}. Forcing ${nextAgent}.`);
                        decision = {
                            action: 'delegate',
                            nextAgent: nextAgent,
                            reasoning: `Coverage insufficient: ${coverage.reason}. Mandatory security checks or surface mapping incomplete.`
                        };
                    }
                }

                if (decision.updateFinding) {
                    const update = decision.updateFinding;
                    const targetFinding = context.vulnerabilities.find(v => !v.verified);
                    if (targetFinding) {
                        Object.assign(targetFinding, update);
                        this.logger.logDebug(`[${currentAgent.name}] Updated finding: ${targetFinding.description} (Confidence: ${targetFinding.confidence})`);
                    }
                }

                if (decision.action === 'stop') {
                    this.logger.logDebug(`Agent ${currentAgent.name} requested stop. Reasoning: ${decision.reasoning}`);
                    context.state = 'analyzing';
                    break;
                }

                if (decision.action === 'delegate' && decision.nextAgent) {
                    const next = this.registeredAgents.get(decision.nextAgent) || (decision.nextAgent === 'OrchestratorAgent' ? orchestrator : null);
                    if (next) {
                        if (decision.nextAgent === 'OrchestratorAgent' && currentAgent.name !== 'OrchestratorAgent') {
                            context.stagnationCounter++;
                        }
                        currentAgent = next;
                        this.currentAgentStepCount = 0;
                        this.lastToolName = null;
                        this.lastTarget = null;
                        this.toolRepeatCount = 0;
                        continue;
                    } else {
                        currentAgent = orchestrator;
                        this.currentAgentStepCount = 0;
                        continue;
                    }
                }

                if (decision.action === 'run_tool' && decision.tool) {
                    const currentTarget = decision.input?.target || context.target;

                    if (decision.tool === this.lastToolName && currentTarget === this.lastTarget) {
                        this.toolRepeatCount++;
                        if (this.toolRepeatCount >= this.MAX_TOOL_REPEATS) {
                            this.logger.logDebug(`Tool ${decision.tool} on ${currentTarget} repeated. Forcing Orchestrator takeover.`);
                            currentAgent = orchestrator;
                            this.currentAgentStepCount = 0;
                            this.lastToolName = null;
                            this.lastTarget = null;
                            this.toolRepeatCount = 0;
                            continue;
                        }
                    } else {
                        this.lastToolName = decision.tool;
                        this.lastTarget = currentTarget;
                        this.toolRepeatCount = 0;
                    }

                    await this.logger.updateStatus(context.jobId, `[${currentAgent.name}] Executing tool: ${decision.tool}...`, estimatedProgress);

                    let toolInput = decision.input || { target: context.target };
                    if (typeof toolInput === 'object') {
                        if (!toolInput.target || toolInput.target === 'undefined' || toolInput.target === 'null') {
                            (toolInput as any).target = context.target;
                        }
                    }
                    if (typeof toolInput === 'string') {
                        toolInput = { target: toolInput };
                    }

                    let executionResult;
                    try {
                        executionResult = await this.toolExecutor.executeTool(
                            decision.tool,
                            toolInput as any,
                            context
                        );
                    } catch (e: any) {
                        this.logger.logDebug(`Tool execution failed critically: ${e.message}`);
                        executionResult = {
                            result: { findings: [], error: e.message },
                            telemetry: {
                                tool: decision.tool,
                                input: toolInput,
                                duration: 0,
                                requests: 0,
                                success: false,
                                result: {},
                                error: e.message,
                                timestamp: new Date().toISOString()
                            }
                        };
                    }

                    const { result, telemetry } = executionResult;

                    context.investigationMemory[decision.tool] = context.investigationMemory[decision.tool] || [];
                    if (!context.investigationMemory[decision.tool].includes(currentTarget)) {
                        context.investigationMemory[decision.tool].push(currentTarget);
                    }

                    const isUseful = telemetry.success && (result.findings?.length > 0 || Object.keys(result.data || {}).length > 0);

                    if (!isUseful) {
                        context.stagnationCounter++;
                    } else {
                        context.stagnationCounter = 0;
                    }

                    if (decision.tool) {
                        this.normalizeToolResult(context, decision.tool, result);

                        this.updateAttackGraph(context, {
                            id: `tool-${decision.tool}`,
                            type: 'service',
                            label: decision.tool,
                            metadata: { result: isUseful ? 'useful' : 'empty' }
                        }, 'root', 'contains');

                        if (context.currentPlan) {
                            const relatedObjective = (context.currentPlan.objectives as any[]).find((o: any) =>
                                o.status === 'pending' &&
                                (decision.reasoning.toLowerCase().includes(o.description.toLowerCase()) ||
                                    (decision.tool && o.description.toLowerCase().includes(decision.tool.toLowerCase())))
                            );
                            if (relatedObjective) {
                                relatedObjective.status = isUseful ? 'completed' : 'failed';
                            }
                        }
                    }

                    context.toolsUsed++;
                    context.requestsMade += (telemetry.requests || 0);
                    (telemetry as any).agent = currentAgent.name;
                    context.telemetry.push(telemetry);

                    if (!telemetry.success) {
                        if (this.isPolicyBlockError(telemetry.error)) {
                            this.policyBlockCounter++;
                        }
                    }

                    if (result.findings?.length) {
                        const newFindings = result.findings.map((f: string) => {
                            const isInfoTool = ['http_probe', 'endpoint_discovery', 'js_endpoint_miner', 'web_crawler', 'robots_explorer', 'sitemap_analyzer'].includes(decision.tool!);
                            return {
                                type: decision.tool || 'ToolFinding',
                                description: f,
                                severity: isInfoTool ? 'INFO' : 'LOW',
                                confidence: isInfoTool ? 1.0 : 0.7,
                                evidence: result.data ? [JSON.stringify(result.data)] : []
                            } as Finding;
                        });

                        for (const finding of newFindings) {
                            // Enrich finding with mission metadata
                            finding.agent = currentAgent.name;
                            finding.endpoint = (decision.input as any)?.target || context.target;
                            finding.parameter = (decision.input as any)?.parameter;
                            finding.payload = (decision.input as any)?.payload || (decision.input as any)?.body;

                            const isDuplicate = context.vulnerabilities.some(v =>
                                v.description === finding.description && v.endpoint === finding.endpoint
                            );
                            if (!isDuplicate) {
                                context.vulnerabilities.push(finding);
                                const targetNodeId = (decision.input as any)?.metadata?.targetNode || `tool-${decision.tool}`;
                                this.updateAttackGraph(context, {
                                    id: `vuln-${decision.tool}-${context.vulnerabilities.length}`,
                                    type: 'vulnerability',
                                    label: finding.description
                                }, targetNodeId, 'vulnerable_to');
                            }
                        }
                    }
                }
            } catch (e) {
                this.logger.logDebug(`Error during investigation loop: ${e}`);
                context.state = 'failed';
                break;
            }
        }

        return context;
    }

    private normalizeToolResult(context: ScanContext, toolName: string, result: any) {
        if (!result.data) return;

        switch (toolName) {
            case 'http_probe':
                if (result.data.technologies) {
                    context.technologies = Array.from(new Set([...context.technologies, ...result.data.technologies]));
                }
                if (result.data.headers) {
                    context.headers = { ...context.headers, ...result.data.headers };
                }
                break;
            case 'endpoint_discovery':
            case 'web_crawler':
            case 'sitemap_analyzer':
            case 'robots_explorer':
                const endpoints = result.data.endpoints || result.data.paths || [];
                if (endpoints.length > 0) {
                    context.discoveredEndpoints = Array.from(new Set([...context.discoveredEndpoints, ...endpoints]));
                    endpoints.forEach((path: string) => {
                        this.updateAttackGraph(context, {
                            id: `endpoint:${path}`,
                            type: 'endpoint',
                            label: path
                        }, 'root', 'contains');
                    });
                }
                const pgs = result.data.pages || [];
                if (pgs.length > 0) {
                    context.discoveredPages = Array.from(new Set([...context.discoveredPages, ...pgs]));
                    pgs.forEach((path: string) => {
                        this.updateAttackGraph(context, {
                            id: `page:${path}`,
                            type: 'target',
                            label: path
                        }, 'root', 'contains');
                    });
                }
                break;
            case 'js_endpoint_miner':
                if (result.data.endpoints) {
                    const newEndpoints = result.data.endpoints as string[];
                    context.discoveredEndpoints = Array.from(new Set([...context.discoveredEndpoints, ...newEndpoints]));
                    const potentialPages = newEndpoints.filter(e => e.startsWith('/') && !e.includes('.'));
                    context.discoveredPages = Array.from(new Set([...context.discoveredPages, ...potentialPages]));
                    newEndpoints.forEach((path: string) => {
                        this.updateAttackGraph(context, {
                            id: `endpoint:${path}`,
                            type: 'endpoint',
                            label: path
                        }, 'root', 'contains');
                    });
                }
                break;
            case 'subdomain_discovery':
                if (result.data.subdomains) {
                    const subs = result.data.subdomains as string[];
                    subs.forEach(s => {
                        this.updateAttackGraph(context, {
                            id: `subdomain:${s}`,
                            type: 'service',
                            label: s,
                            metadata: { source: 'crt.sh' }
                        }, 'root', 'identifies');
                    });
                }
                break;
            case 'historical_discovery':
                if (result.data.urls) {
                    const urls = result.data.urls as string[];
                    context.discoveredEndpoints = Array.from(new Set([...context.discoveredEndpoints, ...urls]));
                    urls.forEach(u => {
                        this.updateAttackGraph(context, {
                            id: `historical:${u}`,
                            type: 'endpoint',
                            label: u,
                            metadata: { source: 'wayback' }
                        }, 'root', 'leads_to');
                    });
                }
                break;
            case 'parameter_fuzzer':
                if (result.data.discovered) {
                    const params = result.data.discovered as string[];
                    params.forEach(p => {
                        this.updateAttackGraph(context, {
                            id: `param:${p}`,
                            type: 'service',
                            label: `Param: ${p}`
                        }, 'root', 'contains');
                    });
                }
                break;
        }
    }

    private checkCoverage(context: ScanContext): { sufficient: boolean, reason?: string, recommendedAgent?: string } {
        const isSPA = context.technologies.some(t => ['Next.js', 'React', 'Vercel', 'Vue', 'Angular'].includes(t));
        const minPages = isSPA ? 1 : 3;
        const minEndpoints = 5;

        const reconAttempts = context.telemetry.filter(t => (t as any).agent === 'ReconAgent').length;
        const tooManyReconAttempts = reconAttempts >= 10;

        if (context.discoveredPages.length < minPages && !tooManyReconAttempts) {
            return {
                sufficient: false,
                reason: `Only ${context.discoveredPages.length}/${minPages} pages discovered.${isSPA ? ' (SPA mode)' : ''}`,
                recommendedAgent: 'ReconAgent'
            };
        }
        if (context.discoveredEndpoints.length < minEndpoints && !tooManyReconAttempts) {
            return {
                sufficient: false,
                reason: `Only ${context.discoveredEndpoints.length}/${minEndpoints} endpoints discovered.`,
                recommendedAgent: 'ReconAgent'
            };
        }

        const toolsRun = new Set(context.telemetry.map(t => t.tool));
        const checks = [
            { tool: 'subdomain_discovery', agent: 'SurfaceExpansionAgent' },
            { tool: 'historical_discovery', agent: 'SurfaceExpansionAgent' },
            { tool: 'header_analysis', agent: 'WebSecurityAgent' },
            { tool: 'javascript_secret_scan', agent: 'SecretsDiscoveryAgent' },
            { tool: 'dependency_cve_lookup', agent: 'DependencyAgent' },
            { tool: 'payload_fuzz', agent: 'PayloadAgent' }
        ];

        for (const check of checks) {
            if (!toolsRun.has(check.tool)) {
                const toolAttempts = context.telemetry.filter(t => t.tool === check.tool).length;
                if (toolAttempts >= 2) continue;

                return {
                    sufficient: false,
                    reason: `Critical security check ${check.tool} not yet performed.`,
                    recommendedAgent: check.agent
                };
            }
        }

        return { sufficient: true };
    }

    private evaluateInvestigationCompletion(context: ScanContext): { complete: boolean; reason?: string } {
        const toolsRun = new Set(context.telemetry.map(t => t.tool));

        const reconComplete = context.discoveredPages.length >= 1 && context.discoveredEndpoints.length >= 5;
        const surfaceMappingComplete = toolsRun.has('header_analysis');
        const vulnAnalysisComplete = toolsRun.has('javascript_secret_scan') && toolsRun.has('dependency_cve_lookup');
        const verificationComplete = toolsRun.has('payload_fuzz') || toolsRun.has('verify') || toolsRun.has('sqlmap');

        if (reconComplete && surfaceMappingComplete && vulnAnalysisComplete && verificationComplete) {
            return { complete: true, reason: 'Core phase checks completed.' };
        }

        return { complete: false };
    }

    private isPolicyBlockError(error?: string): boolean {
        if (!error) return false;
        return /(security policy|forbidden|blocked|denied|unauthorized|rate limit|429)/i.test(error);
    }

    private updateAttackGraph(
        context: ScanContext,
        node: GraphNode,
        parentId?: string,
        relationship?: 'contains' | 'exposed_at' | 'vulnerable_to' | 'identifies' | 'leads_to'
    ) {
        if (!context.attackGraph) {
            context.attackGraph = { nodes: [], edges: [] };
        }

        const existingNode = context.attackGraph.nodes.find(n => n.id === node.id);
        if (!existingNode) {
            context.attackGraph.nodes.push(node);
        }

        if (parentId && relationship) {
            const edgeExists = context.attackGraph.edges.some(e =>
                e.from === parentId && e.to === node.id && (e as any).type === relationship
            );
            if (!edgeExists) {
                context.attackGraph.edges.push({
                    from: parentId,
                    to: node.id,
                    type: relationship as any
                });
            }
        }
    }

    private isBudgetExhausted(context: ScanContext): boolean {
        const elapsed = Date.now() - context.startTime;
        if (elapsed >= this.budget.maxTime) {
            return true;
        }

        if (context.toolsUsed >= this.budget.maxTools) return true;
        if (context.requestsMade >= this.budget.maxRequests) return true;
        if (this.totalSteps >= this.MAX_TOTAL_STEPS) {
            return true;
        }

        return false;
    }
}
