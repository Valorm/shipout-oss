import { Agent, AgentDecision } from '@shared/types/agent';
import { ScanContext } from '@shared/types/scan-context';

export class ReconAgent implements Agent {
    public name = 'ReconAgent';
    public description = 'Discovers the attack surface using http_probe and endpoint_discovery.';
    public usesGemini = false; // Note: We keep this largely deterministic for v1.

    public async decide(context: ScanContext): Promise<AgentDecision> {

        // Deterministic state machine for Recon

        // Step 1: Probe
        const hasProbed = context.telemetry.some(t => t.tool === 'http_probe' && t.success);
        if (!hasProbed) {
            return {
                action: 'run_tool',
                tool: 'http_probe',
                reasoning: 'Need to verify if target is alive and check basic server headers.'
            };
        }

        // Step 1.5: Deep Recon (Robots & Sitemap)
        const runMemory = (tool: string, target: string) => (context.investigationMemory[tool] || []).includes(target);

        if (!runMemory('robots_explorer', context.target)) {
            return {
                action: 'run_tool',
                tool: 'robots_explorer',
                reasoning: 'Checking robots.txt for hidden paths.'
            };
        }

        if (!runMemory('sitemap_analyzer', context.target)) {
            return {
                action: 'run_tool',
                tool: 'sitemap_analyzer',
                reasoning: 'Analyzing sitemap.xml for page structure.'
            };
        }

        // Step 2: Endpoint mapping
        const hasEndpointMapped = context.telemetry.some(t => t.tool === 'endpoint_discovery' && t.success);
        if (!hasEndpointMapped) {
            return {
                action: 'run_tool',
                tool: 'endpoint_discovery',
                reasoning: 'Need to map out the available endpoints on the reachable target.'
            };
        }

        // Step 2.5: Page Crawling
        const crawlTelemetries = context.telemetry.filter(t => t.tool === 'web_crawler');
        const crawlCount = crawlTelemetries.filter(t => t.success).length;

        // Flexible Coverage: If we have many endpoints, we can relax page requirements
        const isCoverageSufficient = context.discoveredPages.length >= 3 ||
            (context.discoveredPages.length >= 1 && context.discoveredEndpoints.length >= 10);

        const rootCrawlAttempted = runMemory('web_crawler', context.target);

        if (!isCoverageSufficient && crawlCount < 5) {
            const alreadyCrawled = context.investigationMemory['web_crawler'] || [];
            const nextLink = context.discoveredEndpoints
                .map(e => new URL(e, context.target).toString())
                .find(url => !alreadyCrawled.includes(url));

            if (nextLink || (crawlCount === 0 && !rootCrawlAttempted)) {
                return {
                    action: 'run_tool',
                    tool: 'web_crawler',
                    input: { target: nextLink || context.target },
                    reasoning: `Coverage insufficient. Running crawler on ${nextLink || 'target root'}.`
                };
            }
        }

        // Done with initial recon, return control to Orchestrator
        return {
            action: 'delegate',
            nextAgent: 'OrchestratorAgent',
            reasoning: 'Basic surface mapping complete. Handing off to deep discovery agents.'
        };
    }
}
