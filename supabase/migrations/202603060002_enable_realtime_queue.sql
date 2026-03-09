-- Enable Supabase Realtime for queue tables to allow instant worker pickup
DO $$
BEGIN
  -- Add jobs table
  BEGIN
    ALTER PUBLICATION supabase_realtime ADD TABLE jobs;
  EXCEPTION
    WHEN duplicate_object THEN NULL;
  END;

  -- Add tool_jobs table
  BEGIN
    ALTER PUBLICATION supabase_realtime ADD TABLE tool_jobs;
  EXCEPTION
    WHEN duplicate_object THEN NULL;
  END;
END $$;
