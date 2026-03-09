import { executeScanJob } from './worker';
import fs from 'fs';
import { getAdminClient } from '../../services/database/db';

/**
 * Standalone entrypoint for the Fly.io Machine worker.
 * Reads job configuration from environment variables.
 * If env vars are missing, transitions into a continuous polling mode to pick up tool_jobs from the queue.
 */
async function main() {
    console.log('[Worker Entrypoint] Initializing...');

    const jobId = process.env.JOB_ID;
    const target = process.env.TARGET;
    const type = process.env.JOB_TYPE as 'url' | 'repo';
    const identityString = process.env.JOB_IDENTITY;

    // If we have job context, run once and exit (ephemeral mode)
    if (jobId && target && type && identityString) {
        console.log(`[Worker Entrypoint] Starting ephemeral job ${jobId}...`);
        await runSingleJob(jobId, target, type, identityString);
        process.exit(0);
    }

    // No job context — transition to continuous polling mode (persistent mode)
    console.log('[Worker Entrypoint] No direct job context. Transitioning to continuous polling mode...');

    // Check for Supabase connectivity
    if (!process.env.SUPABASE_URL || !process.env.SUPABASE_SERVICE_ROLE_KEY) {
        console.error('[Worker Entrypoint] Error: Missing SUPABASE_URL or SUPABASE_SERVICE_ROLE_KEY. Cannot start polling mode.');
        process.exit(1);
    }

    await runPollingLoop();
}

async function runSingleJob(jobId: string, target: string, type: 'url' | 'repo', identityString: string) {
    const toolName = process.env.TOOL_NAME;
    const toolInputString = process.env.TOOL_INPUT;
    const toolJobId = process.env.TOOL_JOB_ID;
    const callbackUrl = process.env.CALLBACK_URL;
    const identity = JSON.parse(identityString);
    const toolInput = toolInputString ? JSON.parse(toolInputString) : undefined;

    try {
        const result = await executeScanJob(jobId, target, type, toolName, toolInput, async (progress, statusText) => {
            console.log(`[Worker Progress] ${progress}%: ${statusText}`);
            if (callbackUrl) {
                try {
                    await fetch(callbackUrl, {
                        method: 'POST',
                        headers: { 'Content-Type': 'application/json' },
                        body: JSON.stringify({ jobId, progress, statusText, status: 'RUNNING', identity })
                    });
                } catch (e) {
                    console.warn('[Worker Entrypoint] Failed to report progress to callback:', e);
                }
            }
        });

        console.log('[Worker Entrypoint] Job completed successfully.');

        if (callbackUrl) {
            await fetch(callbackUrl, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({
                    jobId,
                    toolJobId,
                    status: 'COMPLETED',
                    payload: result.toolResult,
                    identity
                })
            });
        }

        fs.writeFileSync('/tmp/job-result.json', JSON.stringify(result));
    } catch (error: any) {
        console.error('[Worker Entrypoint] Job failed:', error);
        if (callbackUrl) {
            try {
                await fetch(callbackUrl, {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ jobId, status: 'FAILED', error: error.message, identity })
                });
            } catch (e) { }
        }
        throw error;
    }
}

async function runPollingLoop() {
    const supabase = getAdminClient();
    const POLL_INTERVAL = 3000; // 3 seconds

    console.log('[Worker Entrypoint] Polling for tool_jobs...');

    while (true) {
        try {
            const { data: toolJobs, error } = await supabase.rpc('claim_next_tool_job') as { data: any[] | null; error: any };

            if (error) {
                console.error('[Worker Entrypoint] Error claiming job:', error);
                await new Promise(r => setTimeout(r, POLL_INTERVAL * 2));
                continue;
            }

            if (toolJobs && toolJobs.length > 0) {
                const toolJob = toolJobs[0];
                console.log(`[Worker Entrypoint] Picked up tool job ${toolJob.id} (${toolJob.tool_name})`);

                // Fetch scan job context for this tool
                const { data: scanJobRaw } = await supabase.from('jobs').select('*').eq('id', toolJob.scan_job_id).single() as { data: any };
                if (!scanJobRaw) {
                    console.error(`[Worker Entrypoint] Scan job ${toolJob.scan_job_id} not found.`);
                    await (supabase.from('tool_jobs') as any).update({ status: 'FAILED' }).eq('id', toolJob.id);
                    continue;
                }

                try {
                    const result = await executeScanJob(
                        scanJobRaw.id,
                        scanJobRaw.target,
                        scanJobRaw.type,
                        toolJob.tool_name,
                        toolJob.input_payload || {},
                        async (progress, statusText) => {
                            console.log(`[Worker Progress] Job ${toolJob.id}: ${progress}% - ${statusText}`);
                            await (supabase.from('tool_jobs') as any).update({
                                progress,
                                status_text: statusText
                            }).eq('id', toolJob.id);
                        }
                    );

                    // Update tool job with result
                    await (supabase.from('tool_jobs') as any).update({
                        status: 'COMPLETED',
                        completed_at: new Date().toISOString()
                    }).eq('id', toolJob.id);

                    await (supabase.from('tool_results') as any).upsert({
                        tool_job_id: toolJob.id,
                        result: result.toolResult || {},
                        created_at: new Date().toISOString()
                    });

                    console.log(`[Worker Entrypoint] Tool job ${toolJob.id} completed.`);
                } catch (e: any) {
                    console.error(`[Worker Entrypoint] Tool job ${toolJob.id} failed:`, e);
                    await (supabase.from('tool_jobs') as any).update({
                        status: 'FAILED',
                        completed_at: new Date().toISOString()
                    }).eq('id', toolJob.id);

                    await (supabase.from('tool_results') as any).upsert({
                        tool_job_id: toolJob.id,
                        error_message: e.message,
                        created_at: new Date().toISOString()
                    });
                }

                // Immediate check for next job without waiting
                continue;
            }
        } catch (e) {
            console.error('[Worker Entrypoint] Unexpected error in polling loop:', e);
        }

        await new Promise(r => setTimeout(r, POLL_INTERVAL));
    }
}

main().catch(err => {
    console.error('[Worker Entrypoint] Fatal transition error:', err);
    process.exit(1);
});
