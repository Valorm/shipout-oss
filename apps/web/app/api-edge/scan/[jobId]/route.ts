import { NextResponse } from "next/server";
import { db } from "../../../../services/database/db";
import { createClient } from "@/utils/supabase/server";

const corsHeaders = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
  "Access-Control-Allow-Headers": "Content-Type, Authorization"
};

export async function OPTIONS() {
  return new Response(null, { status: 200, headers: corsHeaders });
}

// POLLING REPORT SERVICE ENDPOINT
// The frontend polls this endpoint, which queries the database for the completed scan result.
// Uses the admin client (bypasses RLS) so it works for both authenticated and anonymous users.
export async function GET(req: Request, { params }: { params: Promise<{ jobId: string }> }) {
  return handleJobLookup(req, params);
}

export async function POST(req: Request, { params }: { params: Promise<{ jobId: string }> }) {
  return handleJobLookup(req, params);
}

async function handleJobLookup(req: Request, params: Promise<{ jobId: string }>) {
  try {
    const resolvedParams = await params;
    const jobId = resolvedParams.jobId;

    const supabase = await createClient();
    const { data: { user } } = await supabase.auth.getUser();

    // Use admin client directly for job polling, with app-layer authorization checks.
    // Anonymous jobs (user_id is null) can be polled by anyone with the jobId.
    // Authenticated jobs require the caller to match the owner.
    const job = await db.getJob(jobId);

    if (!job) {
      return NextResponse.json({ error: "Job not found" }, { status: 404, headers: corsHeaders });
    }

    if (job.user_id && (!user || user.id !== job.user_id)) {
      return NextResponse.json({ error: "Unauthorized" }, { status: 401, headers: corsHeaders });
    }

    const isTerminal = ['COMPLETED', 'FAILED', 'BLOCKED'].includes(job.status);

    // REDACTION LAYER: Ensure no sensitive keys leak in logs or results.
    const redact = (val: any): any => {
      if (typeof val === 'string') {
        return val
          .replace(/(bearer\s+)[^\s]+/gi, "$1[REDACTED]")
          .replace(/(token|secret|api[_-]?key|password)\s*[:=]\s*[^\s,;]+/gi, "$1=[REDACTED]")
          .replace(/sk-[a-z0-9]{16,}/gi, "[REDACTED_API_KEY]");
      }
      if (Array.isArray(val)) return val.map(redact);
      if (typeof val === 'object' && val !== null) {
        const redacted: any = {};
        for (const key in val) {
          redacted[key] = redact(val[key]);
        }
        return redacted;
      }
      return val;
    };

    if (!isTerminal) {
      return NextResponse.json({
        jobId: job.id,
        status: job.status,
        progress: job.progress,
        status_text: job.statusText ? redact(job.statusText) : job.statusText,
      }, { headers: corsHeaders });
    }

    return NextResponse.json(redact({
      jobId: job.id,
      status: job.status,
      progress: job.progress,
      status_text: job.statusText,
      score: job.score,
      confidence: job.confidence,
      coverage: job.coverage,
      checksCompleted: job.checksCompleted,
      totalChecks: job.totalChecks,
      critical_issues: job.criticalIssues,
      warnings: job.warnings,
      fixes: job.fixes,
      risk_categories: job.riskCategories,
      checklist: job.checklist,
      investigation_steps: job.investigationSteps || [],
      completedAt: job.completedAt
    }), { headers: corsHeaders });

  } catch (e: any) {
    console.error("[Polling] Failed to fetch job:", e);
    return NextResponse.json({ error: "Failed to fetch report" }, { status: 500, headers: corsHeaders });
  }
}
