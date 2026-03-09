import { getAdminClient, getSupabaseClient } from './db';

export const metrics = {
    increment: async (key: string): Promise<void> => {
        const client = getAdminClient();
        try {
            // @ts-ignore - Supabase client signature expects undefined args when untyped
            const { error } = await client.rpc('increment_metric', { metric_key: key });
            if (error) throw error;
        } catch (e) {
            console.error(`[Metrics] Failed to increment ${key}:`, e);
        }
    },

    getAll: async (): Promise<Record<string, number>> => {
        const client = getAdminClient();
        const { data, error } = await client
            .from('system_metrics')
            .select('key, value');

        if (error) {
            console.error('[Metrics] Failed to fetch metrics:', error);
            return {};
        }

        return (data || []).reduce((acc: any, curr: any) => {
            acc[curr.key] = curr.value;
            return acc;
        }, {});
    }
};
