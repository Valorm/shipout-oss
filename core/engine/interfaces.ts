import { ScanContext, ToolTelemetry } from '../../packages/shared/types/scan-context';
import { ToolInput, ToolOutput } from '../../packages/shared/types/tool';

export interface ToolExecutor {
    executeTool(
        toolName: string,
        input: ToolInput,
        context: ScanContext
    ): Promise<{ result: ToolOutput; telemetry: ToolTelemetry }>;
}

export interface InvestigationLogger {
    updateStatus(jobId: string, text: string, progress?: number): Promise<void>;
    logDebug(message: string): void;
}
