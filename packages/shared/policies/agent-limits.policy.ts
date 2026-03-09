export const AgentLimitsPolicy = {
    MAX_INVESTIGATION_STEPS: 8,      // Max orchestrator iterations
    MAX_TOOLS_PER_STEP: 3,            // Max tools run per iteration  
    MAX_REQUESTS_PER_TOOL: 10,        // Max HTTP requests a single tool can make
    MAX_TOTAL_REQUESTS_PER_SCAN: 50,  // Hard cap across all tools
    MAX_RESPONSE_SIZE_BYTES: 100_000, // Max response body to retain in memory per request
    AI_DECISIONS_MAX: 5,              // Max times AI is consulted for tool selection
} as const;

export type AgentLimits = typeof AgentLimitsPolicy;
