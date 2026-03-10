import { ScanContext, Finding, GraphNode } from '../../packages/shared/types/scan-context';
import { Agent } from '../../packages/shared/types/agent';
import { ToolExecutor, InvestigationLogger } from './interfaces';

export class ParallelPlanner {
    private registeredAgents: Map<string, Agent> = new Map();
    private toolExecutor: ToolExecutor;
    private logger: InvestigationLogger;

    // Reliability Guardrails
    private totalSteps: number = 0;
    private readonly MAX_TOTAL_STEPS = 60;
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

        this.logger.logDebug(`Starting real parallel investigation (Concurrency: ${concurrency})`);

        // Update Attack Graph Root
        this.updateAttackGraph(context, {
            id: 'root',
            type: 'target',
            label: context.target
        });

        // 1. Initial Recon (Sequential start to seed queues)
        await this.runSequentially(['ReconAgent'], context);

        // 2. Parallel Lanes
        const lanes = [
            this.runDiscoveryLane(context),
            this.runPayloadPool(context, Math.max(1, Math.floor(concurrency * 0.7))),
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

    private async runSequentially(agentNames: string[], context: ScanContext) {
        for (const name of agentNames) {
            const agent = this.registeredAgents.get(name);
            if (!agent) continue;
            await this.executeAgentCycle(agent, context);
        }
    }

    private async runDiscoveryLane(context: ScanContext) {
        const expansionAgent = this.registeredAgents.get('SurfaceExpansionAgent');
        const reconAgent = this.registeredAgents.get('ReconAgent');

        while (this.isInvestigating(context)) {
            if (reconAgent) await this.executeAgentCycle(reconAgent, context);
            if (expansionAgent) await this.executeAgentCycle(expansionAgent, context);
            await new Promise(r => setTimeout(r, 2000));
        }
    }

    private async runPayloadPool(context: ScanContext, workerCount: number) {
        const payloadAgent = this.registeredAgents.get('PayloadAgent');
        if (!payloadAgent) return;

        const workers = Array(workerCount).fill(0).map(async (_, i) => {
            while (this.isInvestigating(context)) {
                if (context.discoveryQueue.length > 0) {
                    const target = context.discoveryQueue.shift();
                    if (target) {
                        await this.executeAgentCycle(payloadAgent, { ...context, target });
                    }
                } else {
                    await new Promise(r => setTimeout(r, 1000));
                }
            }
        });

        await Promise.all(workers);
    }

    private async runPassiveLane(context: ScanContext) {
        const secretsAgent = this.registeredAgents.get('SecretsDiscoveryAgent');
        const dataLeakAgent = this.registeredAgents.get('DataLeakAgent');
        const formAgent = this.registeredAgents.get('FormAnalysisAgent');

        while (this.isInvestigating(context)) {
            if (secretsAgent) await this.executeAgentCycle(secretsAgent, context);
            if (dataLeakAgent) await this.executeAgentCycle(dataLeakAgent, context);
            if (formAgent) await this.executeAgentCycle(formAgent, context);
            await new Promise(r => setTimeout(r, 3000));
        }
    }

    private async executeAgentCycle(agent: Agent, context: ScanContext) {
        try {
            await this.logger.updateStatus(context.jobId, `[${agent.name}] ${agent.description.split('.')[0]}...`);
            const decision = await agent.decide(context);
            if (decision.action === 'run_tool' && decision.tool) {
                const toolInput = decision.input || { target: context.target };
                // Ensure target is present for ToolInput compliance
                if (!toolInput.target) toolInput.target = context.target;

                const resultSize = await this.toolExecutor.executeTool(
                    decision.tool,
                    toolInput as any, // Cast to any to avoid complex interface mapping in this loop
                    context
                );

                this.totalSteps++;
                this.processToolResult(context, agent, decision.tool, resultSize);
            }
        } catch (e: any) {
            this.logger.logDebug(`[${agent.name}] Cycle failed: ${e.message}`);
        }
    }

    private processToolResult(context: ScanContext, agent: Agent, toolName: string, execution: any) {
        const { result, telemetry } = execution;

        // 1. Telemetry & Budget
        context.telemetry.push({ ...telemetry, agent: agent.name });
        context.toolsUsed++;
        context.requestsMade += (telemetry.requests || 0);

        if (!result.data) return;

        // 2. Comprehensive Normalization (Real Logic)
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
            case 'js_endpoint_miner':
            case 'historical_discovery':
                const endpoints = result.data.endpoints || result.data.paths || result.data.urls || [];
                if (endpoints.length > 0) {
                    endpoints.forEach((path: string) => {
                        if (!context.discoveredEndpoints.includes(path)) {
                            context.discoveredEndpoints.push(path);
                            // Feed discovery queue for parallel payload workers
                            context.discoveryQueue.push(path);

                            this.updateAttackGraph(context, {
                                id: `endpoint:${path}`,
                                type: 'endpoint',
                                label: path
                            }, 'root', 'contains');
                        }
                    });
                }
                const pgs = result.data.pages || [];
                if (pgs.length > 0) {
                    pgs.forEach((path: string) => {
                        if (!context.discoveredPages.includes(path)) {
                            context.discoveredPages.push(path);
                            this.updateAttackGraph(context, {
                                id: `page:${path}`,
                                type: 'target',
                                label: path
                            }, 'root', 'contains');
                        }
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

            case 'parameter_fuzzer':
                if (result.data.discovered) {
                    const params = result.data.discovered as string[];
                    params.forEach(p => {
                        if (!context.parameterQueue.includes(p)) {
                            context.parameterQueue.push(p);
                        }
                        this.updateAttackGraph(context, {
                            id: `param:${p}`,
                            type: 'service',
                            label: `Param: ${p}`
                        }, 'root', 'contains');
                    });
                }
                break;
        }

        // 3. Vulnerability Processing
        if (result.findings?.length) {
            result.findings.forEach((f: string) => {
                const finding: Finding = {
                    type: toolName,
                    description: f,
                    severity: result.data?.severity || 'MEDIUM',
                    confidence: 0.8,
                    agent: agent.name,
                    endpoint: telemetry.input?.target || context.target,
                    evidence: result.data?.evidence
                };
                context.vulnerabilities.push(finding);
                this.updateAttackGraph(context, {
                    id: `vuln-${Date.now()}-${Math.random()}`,
                    type: 'vulnerability',
                    label: f
                }, `root`, 'vulnerable_to');
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
