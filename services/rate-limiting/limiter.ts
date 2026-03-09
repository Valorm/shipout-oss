import { getAdminClient } from '../database/db';

export const PersistentLimiter = {
    checkLimit: async (ip: string, tier: 'STRICT' | 'NORMAL', max: number, windowMs: number): Promise<{ limited: boolean; retryAfter?: number }> => {
        const client = getAdminClient();

        try {
            // @ts-ignore - Supabase untyped rpc signature requires undefined args
            const { data, error } = await client.rpc('check_and_increment_rate_limit', {
                target_ip: ip,
                target_tier: tier,
                max_count: max,
                window_ms: windowMs
            });

            if (error) {
                console.error('[Limiter] RPC error:', error);
                return { limited: false };
            }

            const result = (Array.isArray(data) ? data[0] : data) as any;

            if (!result) return { limited: false };

            return {
                limited: !result.allowed,
                retryAfter: result.allowed ? undefined : result.retry_after_seconds
            };
        } catch (e) {
            console.error('[Limiter] Execution error:', e);
            return { limited: false };
        }
    }
};
