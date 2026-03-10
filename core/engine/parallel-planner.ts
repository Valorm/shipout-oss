import { ScanContext, Finding, GraphNode } from '../../packages/shared/types/scan-context';
import { Agent } from '../../packages/shared/types/agent';
import { ToolExecutor, InvestigationLogger } from './interfaces';
import { createHash } from 'crypto';

export class ParallelPlanner {
    private registeredAgents: Map<string, Agent> = new Map();
    private toolExecutor: ToolExecutor;
    private logger: InvestigationLogger;

    // Reliability Guardrails
    private totalSteps: number = 0;
    private readonly MAX_TOTAL_STEPS = 100;
    private readonly DEFAULT_CONCURRENCY = 5;

    constructor(toolExecutor: ToolExecutor, logger: InvestigationLogger) {
        this.toolExecutor = toolExecutor;
        this.logger = logger;
    }

    public registerAgent(agent: Agent) {
        this.registeredAgents.set(agent.name, agent);
    }

    public async runParallelInvestigate(
        orchestrator: Agent,
        context: ScanContext
    ): Promise<ScanContext> {
        context.state = 'investigating';
        const concurrency = context.budget?.concurrency || this.DEFAULT_CONCURRENCY;

        this.logger.logDebug(`Starting Robust Parallel Investigation (Concurrency: ${concurrency})`);

        // Initialize deduplication hashes if missing
        if (!context.findingHashes) context.findingHashes = [];
        if (!context.taskQueue) context.taskQueue = [];

        // Update Attack Graph Root
        this.updateAttackGraph(context, {
            id: 'root',
            type: 'target',
            label: context.target
        });

        // 1. Initial Recon (Seed the engine)
        const reconAgent = this.registeredAgents.get('ReconAgent');
        if (reconAgent) {
            await this.executeAgentCycle(reconAgent, context);
        }

        // 2. Parallel Lanes with Task-Based Coordination
        const lanes = [
            this.runDiscoveryLane(context),
            this.runWorkerPool(context, concurrency),
            this.runPassiveLane(context)
        ];

        try {
            await Promise.all(lanes);
        } catch (e: any) {
            this.logger.logDebug(`Parallel lane error: ${e.message}`);
        }

        context.state = 'analyzing';
        return context;
    }

    private async runDiscoveryLane(context: ScanContext) {
        const expansionAgent = this.registeredAgents.get('SurfaceExpansionAgent');
        const reconAgent = this.registeredAgents.get('ReconAgent');

        while (this.isInvestigating(context)) {
            // Discovery agents run periodically to find new things
            if (reconAgent) await this.executeAgentCycle(reconAgent, context);
            if (expansionAgent) await this.executeAgentCycle(expansionAgent, context);

            // If discovery is stagnant, we could slow down
            await new Promise(r => setTimeout(r, 5000));
        }
    }

    private async runWorkerPool(context: ScanContext, workerCount: number) {
        // Workers consume tasks from the taskQueue or discoveryQueue
        const workers = Array(workerCount).fill(0).map(async (_, i) => {
            const agent = this.registeredAgents.get('PayloadAgent');
            if (!agent) return;

            while (this.isInvestigating(context)) {
                let targetToTest: string | null = null;

                // Prioritize discoveryQueue for Payload testing
                if (context.discoveryQueue.length > 0) {
                    targetToTest = context.discoveryQueue.shift() || null;
                }

                if (targetToTest) {
                    // Keep executing on this target until agent is done with it
                    let isDoneWithTarget = false;
                    while (!isDoneWithTarget && this.isInvestigating(context)) {
                        const beforeTools = context.toolsUsed;
                        await this.executeAgentCycle(agent, { ...context, target: targetToTest });
                        const afterTools = context.toolsUsed;

                        // If no new tool was run, the agent is likely done with this target
                        if (beforeTools === afterTools) {
                            isDoneWithTarget = true;
                        }
                    }
                } else {
                    await new Promise(r => setTimeout(r, 2000));
                }
            }
        });

        await Promise.all(workers);
    }

    private async runPassiveLane(context: ScanContext) {
        const passiveAgents = [
            'SecretsDiscoveryAgent',
            'DataLeakAgent',
            'FormAnalysisAgent'
        ].map(name => this.registeredAgents.get(name)).filter(Boolean) as Agent[];

        while (this.isInvestigating(context)) {
            for (const agent of passiveAgents) {
                await this.executeAgentCycle(agent, context);
            }
            await new Promise(r => setTimeout(r, 4000));
        }
    }

    private async executeAgentCycle(agent: Agent, context: ScanContext) {
        try {
            const decision = await agent.decide(context);

            if (decision.action === 'run_tool' && decision.tool) {
                const target = decision.input?.target || context.target;

                // Prevent redundant tool execution on the same target
                const memoryKey = decision.tool;
                if ((context.investigationMemory[memoryKey] || []).includes(target)) {
                    return; // Skip if already run
                }

                await this.logger.updateStatus(context.jobId, `[${agent.name}] ${decision.reasoning || 'Executing tool'}`);

                const resultSize = await this.toolExecutor.executeTool(
                    decision.tool,
                    (decision.input || { target: context.target }) as any,
                    context
                );

                this.totalSteps++;

                // Update Memory IMMEDIATELY after successful run
                if (!context.investigationMemory[memoryKey]) context.investigationMemory[memoryKey] = [];
                context.investigationMemory[memoryKey].push(target);

                this.processToolResult(context, agent, decision.tool, resultSize);
            }
        } catch (e: any) {
            this.logger.logDebug(`[${agent.name}] Cycle failed: ${e.message}`);
        }
    }

    private processToolResult(context: ScanContext, agent: Agent, toolName: string, execution: any) {
        const { result, telemetry } = execution;

        context.telemetry.push({ ...telemetry, agent: agent.name });
        context.toolsUsed++;
        context.requestsMade += (telemetry.requests || 0);

        if (!result.data) return;

        // 1. Finding Deduplication & Severity Mapping
        if (result.findings?.length) {
            result.findings.forEach((f: string) => {
                // Generate Fingerprint for Finding Deduplication
                const hash = createHash('md5').update(f).digest('hex');
                if (context.findingHashes.includes(hash)) return; // Skip Duplicate Finding

                context.findingHashes.push(hash);

                // Correct Severity Mapping (Metadata/Recon should be INFO)
                let severity: Finding['severity'] = result.data?.severity || 'MEDIUM';
                if (['http_probe', 'robots_explorer', 'sitemap_analyzer', 'subdomain_discovery', 'endpoint_discovery', 'historical_discovery'].includes(toolName)) {
                    if (!f.toLowerCase().includes('vulnerability') && !f.toLowerCase().includes('leak')) {
                        severity = 'INFO';
                    }
                }

                const finding: Finding = {
                    type: toolName,
                    description: f,
                    severity: severity,
                    confidence: 0.8,
                    agent: agent.name,
                    endpoint: telemetry.input?.target || context.target,
                    evidence: result.data?.evidence
                };

                context.vulnerabilities.push(finding);
                this.updateAttackGraph(context, {
                    id: `vuln-${hash}`,
                    type: 'vulnerability',
                    label: f
                }, `root`, 'vulnerable_to');
            });
        }

        // 2. Artifact Normalization (Sync endpoints, pages, tech)
        this.normalizeData(context, toolName, result.data);
    }

    private normalizeData(context: ScanContext, toolName: string, data: any) {
        const endpoints = data.endpoints || data.paths || data.urls || [];
        endpoints.forEach((path: string) => {
            if (!context.discoveredEndpoints.includes(path)) {
                context.discoveredEndpoints.push(path);
                context.discoveryQueue.push(path);
                this.updateAttackGraph(context, { id: `endpoint:${path}`, type: 'endpoint', label: path }, 'root', 'contains');
            }
        });

        const pages = data.pages || [];
        pages.forEach((p: string) => {
            if (!context.discoveredPages.includes(p)) {
                context.discoveredPages.push(p);
                this.updateAttackGraph(context, { id: `page:${p}`, type: 'target', label: p }, 'root', 'contains');
            }
        });

        if (data.technologies) {
            context.technologies = Array.from(new Set([...context.technologies, ...data.technologies]));
        }
        if (data.headers) {
            context.headers = { ...context.headers, ...data.headers };
        }

        if (toolName === 'parameter_fuzzer' && data.discovered) {
            data.discovered.forEach((p: string) => {
                if (!context.parameterQueue.includes(p)) context.parameterQueue.push(p);
            });
        }
    }

    private isInvestigating(context: ScanContext): boolean {
        if (context.state !== 'investigating') return false;
        if (this.totalSteps >= this.MAX_TOTAL_STEPS) return false;
        if (context.toolsUsed >= (context.budget?.maxTools || 50)) return false;
        return true;
    }

    private updateAttackGraph(context: ScanContext, node: GraphNode, parentId?: string, relationship?: any) {
        if (!context.attackGraph) context.attackGraph = { nodes: [], edges: [] };
        if (!context.attackGraph.nodes.find(n => n.id === node.id)) {
            context.attackGraph.nodes.push(node);
        }
        if (parentId && relationship) {
            context.attackGraph.edges.push({ from: parentId, to: node.id, type: relationship });
        }
    }
}
