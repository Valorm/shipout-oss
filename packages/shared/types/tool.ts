import { ScanContext } from './scan-context';

export interface ToolInput {
    target: string;
    contextParams?: Record<string, any>; // Extra params the agent decides to pass (e.g. specific endpoint)
}

export interface ToolOutput {
    findings: string[];
    data?: any; // Structured data extracted (e.g. { endpoints: [...] })
    error?: string;
    requestsMade?: number;
}

export interface Tool {
    name: string;
    description: string;
    run(input: ToolInput, signal?: AbortSignal): Promise<ToolOutput>;
}
