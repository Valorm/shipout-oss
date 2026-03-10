import { ScanContext } from './scan-context';

export interface AgentDecision {
    action: 'run_tool' | 'stop' | 'delegate';
    tool?: string; // e.g. 'header-analysis'
    input?: Record<string, any>; // Args for the tool
    reasoning: string;
    nextAgent?: string; // If action is 'delegate'
    updateFinding?: Partial<{ confidence: number; verified: boolean; correction: string }>;

    // AI Metrics (for agents using Gemini)
    tokens?: {
        prompt: number;
        completion: number;
        total: number;
    };
    cost?: number;
}

export interface Agent {
    name: string;
    description: string;
    usesGemini: boolean;

    /**
     * Evaluates the current context and decides the *next* action.
     * Does NOT execute the tools directly.
     */
    decide(context: ScanContext): Promise<AgentDecision>;
}
