-- Add investigation_steps column to store the agent's investigation timeline
ALTER TABLE public.jobs
ADD COLUMN IF NOT EXISTS investigation_steps JSONB DEFAULT '[]'::jsonb;
