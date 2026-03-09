-- Migration for tool_jobs and tool_results
-- Allows ScanEngine to dispatch individual tool runs to the worker sandbox

CREATE TYPE tool_status AS ENUM ('PENDING', 'RUNNING', 'COMPLETED', 'FAILED');

CREATE TABLE IF NOT EXISTS tool_jobs (
    id UUID DEFAULT gen_random_uuid() PRIMARY KEY,
    scan_job_id UUID NOT NULL REFERENCES jobs(id) ON DELETE CASCADE,
    tool_name TEXT NOT NULL,
    input_payload JSONB DEFAULT '{}'::jsonb,
    status tool_status DEFAULT 'PENDING'::tool_status,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    started_at TIMESTAMP WITH TIME ZONE,
    completed_at TIMESTAMP WITH TIME ZONE
);

CREATE TABLE IF NOT EXISTS tool_results (
    tool_job_id UUID PRIMARY KEY REFERENCES tool_jobs(id) ON DELETE CASCADE,
    result JSONB DEFAULT '{}'::jsonb,
    telemetry JSONB DEFAULT '{}'::jsonb,
    error_message TEXT,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- Enable RLS (Service role primarily uses these tables)
ALTER TABLE tool_jobs ENABLE ROW LEVEL SECURITY;
ALTER TABLE tool_results ENABLE ROW LEVEL SECURITY;

-- Allow read access for authenticated users to view active tool runs on their scans
CREATE POLICY "Users can read tool jobs for their scans" ON tool_jobs FOR SELECT USING (
    EXISTS (
        SELECT 1 FROM jobs WHERE id = tool_jobs.scan_job_id AND user_id = auth.uid()
    )
);

CREATE POLICY "Anonymous users can read tool jobs for unauth scans" ON tool_jobs FOR SELECT USING (
    EXISTS (
        SELECT 1 FROM jobs WHERE id = tool_jobs.scan_job_id AND user_id IS NULL
    )
);

CREATE POLICY "Users can read tool results for their scans" ON tool_results FOR SELECT USING (
    EXISTS (
        SELECT 1 FROM tool_jobs 
        JOIN jobs ON jobs.id = tool_jobs.scan_job_id 
        WHERE tool_jobs.id = tool_results.tool_job_id AND user_id = auth.uid()
    )
);

CREATE POLICY "Anonymous users can read tool results for unauth scans" ON tool_results FOR SELECT USING (
    EXISTS (
        SELECT 1 FROM tool_jobs 
        JOIN jobs ON jobs.id = tool_jobs.scan_job_id 
        WHERE tool_jobs.id = tool_results.tool_job_id AND user_id IS NULL
    )
);

-- Atomic claim function for tool_jobs
CREATE OR REPLACE FUNCTION claim_next_tool_job()
RETURNS TABLE (
    id UUID,
    scan_job_id UUID,
    tool_name TEXT,
    input_payload JSONB
)
LANGUAGE plpgsql
SECURITY DEFINER
AS $$
DECLARE
    claimed_record RECORD;
BEGIN
    UPDATE tool_jobs
    SET status = 'RUNNING'::tool_status, started_at = NOW()
    WHERE tool_jobs.id = (
        SELECT t.id
        FROM tool_jobs t
        WHERE t.status = 'PENDING'::tool_status
        ORDER BY t.created_at ASC
        FOR UPDATE SKIP LOCKED
        LIMIT 1
    )
    RETURNING tool_jobs.id, tool_jobs.scan_job_id, tool_jobs.tool_name, tool_jobs.input_payload INTO claimed_record;

    IF FOUND THEN
        RETURN QUERY SELECT claimed_record.id, claimed_record.scan_job_id, claimed_record.tool_name, claimed_record.input_payload;
    END IF;
END;
$$;
