-- Fix Realtime publication: updated_at does not exist on jobs table, causing TIMED_OUT errors
ALTER PUBLICATION supabase_realtime ADD TABLE public.jobs (id, status, progress, status_text, user_id);
