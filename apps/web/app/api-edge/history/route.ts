import { NextResponse } from "next/server";
import { db } from "../../../services/database/db";
import { createClient } from '@/utils/supabase/server';

const corsHeaders = {
    "Access-Control-Allow-Origin": "*",
    "Access-Control-Allow-Methods": "GET, OPTIONS",
    "Access-Control-Allow-Headers": "Content-Type, Authorization"
};

export async function OPTIONS() {
    return new Response(null, { status: 200, headers: corsHeaders });
}

export async function GET(req: Request) {
    try {
        const supabase = await createClient();
        const { data: { user }, error: userError } = await supabase.auth.getUser();

        if (userError || !user) {
            return NextResponse.json({ error: "Unauthorized" }, { status: 401, headers: corsHeaders });
        }

        const { data: { session }, error: sessionError } = await supabase.auth.getSession();

        if (sessionError || !session?.access_token) {
            return NextResponse.json({ error: "Unauthorized" }, { status: 401, headers: corsHeaders });
        }

        const jobs = await db.getAllJobs(user.id, session.access_token);

        // Return only summary metadata for history to avoid shipping full scan details
        // for every row to the browser upfront.
        const history = jobs.map(job => ({
            id: job.id,
            target: job.target,
            type: job.type,
            date: job.createdAt,
            status: job.status,
            score: job.score,
            confidence: job.confidence,
            checksCompleted: job.checksCompleted,
            totalChecks: job.totalChecks
        }));

        return NextResponse.json(history, { headers: corsHeaders });
    } catch (e: any) {
        console.error('Error fetching history:', e);
        return NextResponse.json({ error: "Failed to fetch scan history" }, { status: 500, headers: corsHeaders });
    }
}
