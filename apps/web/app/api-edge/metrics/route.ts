import { NextResponse } from 'next/server';
import { metrics } from '../../../services/database/metrics';
import { createClient } from '../../../utils/supabase/server';

const corsHeaders = {
    "Access-Control-Allow-Origin": "*",
    "Access-Control-Allow-Methods": "GET, OPTIONS",
    "Access-Control-Allow-Headers": "Content-Type, Authorization"
};

export async function OPTIONS() {
    return new Response(null, { status: 200, headers: corsHeaders });
}

export async function GET() {
    try {
        const supabase = await createClient();
        const { data: { user } } = await supabase.auth.getUser();

        if (!user) {
            return NextResponse.json({ error: 'Unauthorized' }, { status: 401, headers: corsHeaders });
        }

        const currentMetrics = await metrics.getAll();

        // Only expose specific metrics needed for the public/user dashboard
        const allowedKeys = ['requests_blocked', 'unauthorized_access'];
        const filteredMetrics: Record<string, number> = {};

        allowedKeys.forEach(key => {
            filteredMetrics[key] = currentMetrics[key] || 0;
        });

        return NextResponse.json(filteredMetrics, { headers: corsHeaders });
    } catch (e: any) {
        console.error('[Metrics] Failure:', e);
        const errorMsg = e instanceof Error ? e.message : 'Unknown error';
        // REDACTION: Prevent sensitive leakage in metrics errors
        const redacted = errorMsg.replace(/sk-[a-z0-9]{16,}/gi, "[REDACTED]");

        return NextResponse.json(
            { error: `Internal Server Error: ${redacted}` },
            { status: 500, headers: corsHeaders }
        );
    }
}
