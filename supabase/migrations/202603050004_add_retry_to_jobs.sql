-- Add retry logic columns to jobs table
ALTER TABLE public.jobs 
ADD COLUMN IF NOT EXISTS retry_count INTEGER DEFAULT 0,
ADD COLUMN IF NOT EXISTS last_error TEXT,
ADD COLUMN IF NOT EXISTS next_retry_at TIMESTAMPTZ,
ADD COLUMN IF NOT EXISTS progress INTEGER DEFAULT 0,
ADD COLUMN IF NOT EXISTS status_text TEXT;

-- Index for the job queue polling
CREATE INDEX IF NOT EXISTS idx_jobs_polling ON public.jobs (status, next_retry_at) 
WHERE status = 'PENDING';

-- Atomic function to claim the next job
CREATE OR REPLACE FUNCTION public.claim_next_job()
RETURNS TABLE (
  id UUID,
  target TEXT,
  type TEXT,
  retry_count INTEGER
) AS $$
DECLARE
  claimed_job_id UUID;
BEGIN
  UPDATE public.jobs
  SET status = 'RUNNING', status_text = 'Claimed by worker'
  WHERE jobs.id = (
    SELECT jobs.id FROM public.jobs
    WHERE status = 'PENDING' AND (next_retry_at IS NULL OR next_retry_at <= NOW())
    ORDER BY created_at ASC
    FOR UPDATE SKIP LOCKED
    LIMIT 1
  )
  RETURNING jobs.id INTO claimed_job_id;

  IF claimed_job_id IS NOT NULL THEN
    RETURN QUERY SELECT j.id, j.target, j.type, j.retry_count 
    FROM public.jobs j 
    WHERE j.id = claimed_job_id;
  END IF;
END;
$$ LANGUAGE plpgsql SECURITY DEFINER;
