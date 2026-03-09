export interface AgentContext {
    jobId: string;
    target: string;
    jobType: 'url' | 'repo';
    networkCalls: number;
    discoveredEndpoints: Set<string>;
    discoveredTechnologies: Set<string>;
    toolResults: Record<string, ToolResult>;
    investigationSteps: InvestigationStep[];
    detectedSecrets: Set<string>;
    startTime: number;
    isAborted: boolean;
}

export interface ToolResult {
    toolName: string;
    findings: string[];
    severity?: 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';
    rawData?: string; // Stored small snippet of raw data for AI context
    suggestedNextTools?: string[];
    error?: string;
}

export interface InvestigationStep {
    stepIndex: number;
    timestamp: string;
    reasoning: string;
    toolsExecuted: string[];
    keyFindings: string[];
}

export interface AgentTool {
    name: string;
    description: string;

    /**
     * Determine if this tool should be run based on the current context.
     * This allows tools to be suggested before the AI even asks, 
     * or restricts tools from running if prerequisites aren't met.
     */
    shouldRun(ctx: AgentContext): boolean;

    /**
     * Executes the tool. 
     * Note: Tools should handle their own errors and return them cleanly in ToolResult.
     */
    execute(ctx: AgentContext, signal: AbortSignal): Promise<ToolResult>;
}

export interface InvestigationReport {
    score: number | null;
    confidence?: number;
    coverage?: {
        pages?: number;
        endpoints?: number;
        forms?: number;
        headers?: number;
        scripts?: number;
    };
    checksCompleted?: number;
    totalChecks?: number;
    criticalIssues: string[];
    warnings: string[];
    fixes: { file?: string; description: string; codeSnippet?: string }[];
    riskCategories: string[];
    checklist: { id: string; name: string; status: 'PASS' | 'WARN' | 'FAIL' | 'UNKNOWN'; reason?: string }[];
    investigationSteps: InvestigationStep[]; // The agent timeline
    completedAt: string;
}

export interface AgentConfig {
    maxSteps: number;
    maxToolsPerStep: number;
    maxTotalRequests: number;
    timeoutSeconds: number;
}
