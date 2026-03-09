import { createClient } from '@supabase/supabase-js';
import { WorkerStatus } from '../../packages/shared/schemas/worker.schema';

export interface JobRecord {
    id: string;
    user_id?: string;
    target: string;
    type: 'url' | 'repo';
    status: WorkerStatus;
    progress?: number;
    statusText?: string;
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
    investigationSteps?: any[];
    createdAt: string;
    completedAt?: string;
    scheduled_interval?: string;
    retry_count?: number;
    last_error?: string;
    next_retry_at?: string;
}


// Singleton clients — created once, reused across all calls
let _anonClient: ReturnType<typeof createClient> | null = null;
let _adminClient: ReturnType<typeof createClient> | null = null;

// Resolve env vars: support both NEXT_PUBLIC_* (Vercel) and non-prefixed (Fly.io/Docker)
const getSupabaseUrl = () => process.env.NEXT_PUBLIC_SUPABASE_URL || process.env.SUPABASE_URL!;
const getSupabaseAnonKey = () => process.env.NEXT_PUBLIC_SUPABASE_ANON_KEY || process.env.SUPABASE_ANON_KEY!;

// Anon Key client (respects RLS)
export const getSupabaseClient = () => {
    if (!_anonClient) {
        _anonClient = createClient(
            getSupabaseUrl(),
            getSupabaseAnonKey()
        );
    }
    return _anonClient;
};

// Service Role Key client (bypasses RLS — backend use only)
export const getAdminClient = () => {
    if (!_adminClient) {
        _adminClient = createClient(
            getSupabaseUrl(),
            process.env.SUPABASE_SERVICE_ROLE_KEY!
        );
    }
    return _adminClient;
};

function mapRowToJobRecord(data: any): JobRecord {
    return {
        id: data.id,
        user_id: data.user_id,
        target: data.target,
        type: data.type,
        status: data.status,
        progress: data.progress,
        statusText: data.status_text,
        score: data.score,
        confidence: data.confidence,
        coverage: data.coverage,
        checksCompleted: data.checks_completed,
        totalChecks: data.total_checks,
        criticalIssues: data.critical_issues || [],
        warnings: data.warnings || [],
        fixes: data.fixes || [],
        riskCategories: data.risk_categories || [],
        checklist: data.checklist || [],
        investigationSteps: data.investigation_steps || [],
        createdAt: data.created_at,
        completedAt: data.completed_at,
        scheduled_interval: data.scheduled_interval,
        retry_count: data.retry_count,
        last_error: data.last_error,
        next_retry_at: data.next_retry_at
    };
}

export const db = {
    getJob: async (jobId: string, customToken?: string): Promise<JobRecord | undefined> => {
        let client = getAdminClient();
        if (customToken) {
            // Apply token to a fresh client to enforce RLS on REST API requests
            client = createClient(
                getSupabaseUrl(),
                getSupabaseAnonKey(),
                { global: { headers: { Authorization: `Bearer ${customToken}` } } }
            );
        }

        const { data, error } = await client
            .from('jobs')
            .select('*')
            .eq('id', jobId)
            .single();

        if (error) {
            console.error('db.getJob error:', error);
            return undefined;
        }

        // Map snake_case to camelCase
        if (data) {
            return mapRowToJobRecord(data);
        }
        return undefined;
    },

    getAllJobs: async (userId: string, customToken?: string): Promise<JobRecord[]> => {
        let client = getAdminClient();
        if (customToken) {
            client = createClient(
                getSupabaseUrl(),
                getSupabaseAnonKey(),
                { global: { headers: { Authorization: `Bearer ${customToken}` } } }
            );
        }

        const { data, error } = await client
            .from('jobs')
            .select('*')
            .eq('user_id', userId)
            .order('created_at', { ascending: false });

        if (error) {
            console.error('db.getAllJobs error:', error);
            return [];
        }

        return (data as any[]).map(mapRowToJobRecord);
    },

    createJob: async (job: JobRecord): Promise<void> => {
        const { error } = await getAdminClient()
            .from('jobs')
            .insert({
                id: job.id,
                user_id: job.user_id,
                target: job.target,
                type: job.type,
                status: job.status,
                progress: job.progress,
                status_text: job.statusText,
                score: job.score,
                confidence: job.confidence,
                coverage: job.coverage,
                checks_completed: job.checksCompleted,
                total_checks: job.totalChecks,
                critical_issues: job.criticalIssues,
                warnings: job.warnings,
                fixes: job.fixes,
                risk_categories: job.riskCategories,
                checklist: job.checklist,
                created_at: job.createdAt,
                scheduled_interval: job.scheduled_interval,
                retry_count: job.retry_count,
                last_error: job.last_error,
                next_retry_at: job.next_retry_at,
            } as any);

        if (error) console.error('db.createJob error:', error);
    }
};
