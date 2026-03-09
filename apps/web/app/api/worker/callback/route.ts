import { NextResponse } from 'next/server';
import { getAdminClient, db, JobRecord } from '../../../../services/database/db';
import { verifyServiceIdentity, ServiceIdentity } from '../../../../shared/security-utils/service-identity';

type ScheduledInterval = 'daily' | 'weekly' | 'monthly';

type RecurringSourceJob = Pick<JobRecord, 'target' | 'type' | 'user_id' | 'scheduled_interval'>;

function computeNextRunAt(interval?: string | null): string | null {
    const now = new Date();
    switch (interval) {
        case 'daily':
            now.setDate(now.getDate() + 1);
            return now.toISOString();
        case 'weekly':
            now.setDate(now.getDate() + 7);
            return now.toISOString();
        case 'monthly':
            now.setMonth(now.getMonth() + 1);
            return now.toISOString();
        default:
            return null;
    }
}

async function enqueueRecurringScan(sourceJob: RecurringSourceJob, completedAt?: string) {
    const interval = sourceJob.scheduled_interval as ScheduledInterval | undefined;
    const nextRunAt = computeNextRunAt(interval);
    if (!interval || !nextRunAt) return;

    const recurringJobId = crypto.randomUUID();
    await db.createJob({
        id: recurringJobId,
        user_id: sourceJob.user_id,
        target: sourceJob.target,
        type: sourceJob.type,
        status: 'PENDING',
        score: null,
        criticalIssues: [],
        warnings: [],
        fixes: [],
        riskCategories: [],
        checklist: [],
        createdAt: completedAt || new Date().toISOString(),
        scheduled_interval: interval,
        next_retry_at: nextRunAt,
        statusText: `Scheduled next ${interval} scan.`
    });

    console.log(`[Worker Callback] Enqueued recurring job ${recurringJobId} for ${sourceJob.target} at ${nextRunAt}`);
}

/**
 * Secure callback endpoint for isolated workers.
 * The worker sends progress and final results here.
 */
export async function POST(req: Request) {
    try {
        const body = await req.json();
        const supabase = getAdminClient();

        if (body.toolJobId) {
            // This is a report from a single tool execution
            const { toolJobId, status, payload, error } = body;

            if (status === 'COMPLETED') {
                await (supabase.from('tool_jobs') as any).update({ status: 'COMPLETED', completed_at: new Date().toISOString() }).eq('id', toolJobId);
                await (supabase.from('tool_results') as any).upsert({
                    tool_job_id: toolJobId,
                    result: payload,
                    error_message: null
                });
            } else if (status === 'FAILED') {
                await (supabase.from('tool_jobs') as any).update({ status: 'FAILED', completed_at: new Date().toISOString() }).eq('id', toolJobId);
                await (supabase.from('tool_results') as any).upsert({
                    tool_job_id: toolJobId,
                    result: {},
                    error_message: error || 'Tool execution failed'
                });
            }
            return NextResponse.json({ success: true });
        }

        const { jobId, status, progress, statusText, payload, error, identity } = body;

        // 1. Verify Service Identity (Zero Trust)
        if (!identity || !verifyServiceIdentity(identity as ServiceIdentity, 'worker')) {
            console.error('[Worker Callback] Unauthorized access attempt or invalid identity.');
            return NextResponse.json({ error: 'Unauthorized' }, { status: 401 });
        }

        if (!jobId) {
            return NextResponse.json({ error: 'Missing jobId' }, { status: 400 });
        }

        const { data: sourceJob } = await (supabase.from('jobs') as any)
            .select('target, type, user_id, scheduled_interval')
            .eq('id', jobId)
            .single();

        if (status === 'RUNNING') {
            await (supabase.from('jobs') as any).update({
                progress: progress || 0,
                status_text: statusText || 'Running...',
                status: 'RUNNING'
            }).eq('id', jobId);
        } else if (status === 'COMPLETED') {
            const result = payload;
            const completedAt = result.completedAt || new Date().toISOString();
            await (supabase.from('jobs') as any).update({
                status: 'COMPLETED',
                score: result.score,
                confidence: result.confidence,
                coverage: result.coverage,
                checks_completed: result.checksCompleted,
                total_checks: result.totalChecks,
                critical_issues: result.criticalIssues,
                warnings: result.warnings,
                fixes: result.fixes,
                risk_categories: result.riskCategories,
                checklist: result.checklist,
                investigation_steps: result.investigationSteps || [],
                completed_at: completedAt,
                progress: 100,
                status_text: 'Scan completed successfully.'
            }).eq('id', jobId);

            if (sourceJob) {
                await enqueueRecurringScan(sourceJob as RecurringSourceJob, completedAt);
            }
        } else if (status === 'FAILED') {
            const completedAt = new Date().toISOString();
            await (supabase.from('jobs') as any).update({
                status: 'FAILED',
                status_text: 'Scan failed in isolated environment.',
                last_error: error || 'Unknown error',
                completed_at: completedAt
            }).eq('id', jobId);

            if (sourceJob) {
                await enqueueRecurringScan(sourceJob as RecurringSourceJob, completedAt);
            }
        }

        return NextResponse.json({ success: true });
    } catch (e: any) {
        console.error('[Worker Callback] Fatal error:', e);
        const errorMsg = e instanceof Error ? e.message : 'Unknown error';
        // Use a simple redaction for now
        const redacted = errorMsg.replace(/sk-[a-z0-9]{16,}/gi, "[REDACTED]");

        return NextResponse.json(
            { error: `Internal Server Error: ${redacted}` },
            { status: 500 }
        );
    }
}
