import { NextResponse } from "next/server";
import { forwardToGateway } from "../../../services/gateway-adapter/gateway";
import { generateServiceIdentity } from "../../../shared/security-utils/service-identity";
import { createClient } from "@/utils/supabase/server";

const corsHeaders = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Methods": "POST, OPTIONS",
  "Access-Control-Allow-Headers": "Content-Type, Authorization"
};

type ScanType = "url" | "repo";

function getErrorMessage(error: unknown): string {
  if (error instanceof Error) return error.message;
  if (typeof error === "string") return error;
  return "Unexpected error";
}

function redactSensitiveData(message: string): string {
  return message
    .replace(/(bearer\s+)[^\s]+/gi, "$1[REDACTED]")
    .replace(/(token|secret|api[_-]?key|password)\s*[:=]\s*[^\s,;]+/gi, "$1=[REDACTED]")
    .replace(/sk-[a-z0-9]{16,}/gi, "[REDACTED_API_KEY]");
}

function getPublicErrorMessage(rawMessage: string, status: number): string {
  const redacted = redactSensitiveData(rawMessage);

  if (status >= 500) {
    const detail = ` (Internal Error: ${redacted})`;
    return `Scan request failed. Open browser console for technical details.${detail}`;
  }

  return redacted;
}

function mapGatewayErrorStatus(message: string): number {
  if (/^gateway rejection:/i.test(message)) {
    return 403;
  }

  if (/target is required|invalid repository format|invalid job type|invalid request body/i.test(message)) {
    return 400;
  }

  return 500;
}

export async function OPTIONS() {
  return new Response(null, { status: 200, headers: corsHeaders });
}

// THIN ROUTE: Receptionist only — scan execution handled by Fly.io worker
export async function POST(req: Request) {
  try {
    let body: unknown;

    try {
      body = await req.json();
    } catch {
      return NextResponse.json({ error: "Invalid request body" }, { status: 400, headers: corsHeaders });
    }

    const { target, type, scheduledInterval } = (body as Record<string, unknown>) ?? {};

    if (type !== "url" && type !== "repo") {
      return NextResponse.json({ error: "Invalid scan type. Expected 'url' or 'repo'." }, { status: 400, headers: corsHeaders });
    }

    const trimmedTarget = typeof target === "string" ? target.trim() : "";
    const normalizedScheduledInterval = typeof scheduledInterval === "string" ? scheduledInterval : undefined;
    const normalizedTarget =
      type === "url" && trimmedTarget && !/^https?:\/\//i.test(trimmedTarget)
        ? `https://${trimmedTarget}`
        : trimmedTarget;

    if (!normalizedTarget) {
      return NextResponse.json({ error: "Target is required" }, { status: 400, headers: corsHeaders });
    }

    let userId: string | undefined;

    try {
      const supabase = await createClient();
      const {
        data: { user }
      } = await supabase.auth.getUser();

      // Enforce auth only for repo scans
      if (type === "repo" && !user) {
        return NextResponse.json({ error: "GitHub connection required for repository scans" }, { status: 401, headers: corsHeaders });
      }

      userId = user?.id || undefined;
    } catch (error: unknown) {
      if (type === "repo") {
        console.error("Scan route auth initialization failure:", error);
        return NextResponse.json({ error: "Authentication initialization failed" }, { status: 500, headers: corsHeaders });
      }

      // URL scans may proceed without an authenticated user.
      console.warn("Scan route proceeding without user session:", error);
    }

    // Generate identity for the API Edge (acting as gateway)
    const identity = generateServiceIdentity("api-route");

    // validateInput() & forwardToGateway() — creates PENDING job in database
    const jobId = await forwardToGateway(normalizedTarget, type as ScanType, identity, userId, normalizedScheduledInterval);

    // Return jobId immediately — frontend starts polling
    return NextResponse.json({ jobId, status: "PENDING" }, { headers: corsHeaders });
  } catch (error: unknown) {
    const rawMessage = getErrorMessage(error);
    const status = mapGatewayErrorStatus(rawMessage);
    const publicMessage = getPublicErrorMessage(rawMessage, status);

    console.error("Scan route failure:", error);

    return NextResponse.json({ error: publicMessage }, { status, headers: corsHeaders });
  }
}
