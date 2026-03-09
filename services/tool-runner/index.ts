import { ScanContext, ToolTelemetry } from '../../packages/shared/types/scan-context';
import { ToolInput, ToolOutput } from '../../packages/shared/types/tool';

const TOOL_LOCAL_FALLBACK_MS = Number(process.env.TOOL_LOCAL_FALLBACK_MS) || 15000;
const TOOL_LOCAL_TIMEOUT_MS = Number(process.env.TOOL_LOCAL_TIMEOUT_MS) || 25000;

export class ToolRunner {
    public async executeTool(
        toolName: string,
        input: ToolInput,
        context: ScanContext
    ): Promise<{ result: ToolOutput; telemetry: ToolTelemetry }> {
        const startTime = Date.now();
        let success = false;
        let result: ToolOutput = { findings: [], requestsMade: 0 };
        let errorMsg: string | undefined;

        try {
            console.log(`[ToolRunner] Dispatching ${toolName} to execution sandbox for target: ${input.target}`);

            result = await this.dispatchAndAwaitTool(context.jobId, toolName, input, context);

            success = !result.error;
            errorMsg = result.error;

        } catch (e: any) {
            console.error(`[ToolRunner] Error executing ${toolName}:`, e);
            errorMsg = e.message;
            result = { findings: [], error: e.message };
        }

        const duration = Date.now() - startTime;

        const telemetry: ToolTelemetry = {
            tool: toolName,
            input,
            duration,
            requests: result.requestsMade || 0,
            success,
            result: result.data || {},
            error: errorMsg,
            timestamp: new Date().toISOString()
        };

        return { result, telemetry };
    }

    private async dispatchAndAwaitTool(
        scanJobId: string,
        toolName: string,
        input: ToolInput,
        context: ScanContext
    ): Promise<ToolOutput> {
        const { getAdminClient } = await import('../database/db');
        const supabase = getAdminClient();

        // 1. Create a tool job
        const { data: toolJobData, error: insertError } = await supabase
            .from('tool_jobs')
            .insert({
                scan_job_id: scanJobId,
                tool_name: toolName,
                input_payload: input,
                status: 'PENDING'
            } as any)
            .select()
            .single();

        const toolJob = toolJobData as any;

        if (insertError || !toolJob) {
            throw new Error(`Failed to create tool job: ${insertError?.message}`);
        }

        console.log(`[ToolRunner] Created tool job ${toolJob.id} for ${toolName}. Awaiting result...`);

        // 2. Wait for completion (3 minutes for slow network-bound tools)
        const timeoutMs = 180000;
        const startTime = Date.now();
        let localExecutionTriggered = false;

        while (Date.now() - startTime < timeoutMs) {
            // Re-fetch the tool job to see status
            const { data: checkJobData } = await supabase
                .from('tool_jobs')
                .select('status')
                .eq('id', toolJob.id)
                .single();

            const checkJob = checkJobData as any;

            if (checkJob?.status === 'FAILED') {
                throw new Error(`Worker execution failed for ${toolName}`);
            }

            // Check for results
            const { data: resultRaw } = await supabase
                .from('tool_results')
                .select('*')
                .eq('tool_job_id', toolJob.id)
                .single();

            const resultData = resultRaw as any;

            if (resultData) {
                if (resultData.error_message) {
                    throw new Error(resultData.error_message);
                }
                return resultData.result as ToolOutput;
            }

            // Wait 2 seconds before polling again
            await new Promise(resolve => setTimeout(resolve, 2000));
        }

        throw new Error(`Tool execution timed out after ${timeoutMs}ms`);
    }
}

export const toolRunner = new ToolRunner();
