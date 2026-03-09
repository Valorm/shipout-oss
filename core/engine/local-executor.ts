import { ToolExecutor } from './interfaces';
import { ScanContext, ToolTelemetry } from '../../packages/shared/types/scan-context';
import { ToolInput, ToolOutput } from '../../packages/shared/types/tool';
import { availableTools } from '../tools';

export class LocalExecutor implements ToolExecutor {
    async executeTool(
        toolName: string,
        input: ToolInput,
        context: ScanContext
    ): Promise<{ result: ToolOutput; telemetry: ToolTelemetry }> {
        const tool = (availableTools as any)[toolName];
        if (!tool) throw new Error(`Tool ${toolName} not found`);

        const startTime = Date.now();
        try {
            const result = await tool.run(input);
            return {
                result,
                telemetry: {
                    tool: toolName,
                    input: input,
                    duration: Date.now() - startTime,
                    requests: result.requestsMade || 0,
                    success: true,
                    result: result.data || {},
                    timestamp: new Date().toISOString()
                }
            };
        } catch (e: any) {
            return {
                result: { findings: [], error: e.message },
                telemetry: {
                    tool: toolName,
                    input: input,
                    duration: Date.now() - startTime,
                    requests: 0,
                    success: false,
                    result: {},
                    error: e.message,
                    timestamp: new Date().toISOString()
                }
            };
        }
    }
}
