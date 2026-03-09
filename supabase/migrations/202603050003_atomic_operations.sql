-- Atomic operations for system health and security

-- 1. Atomic Metrics Increment
CREATE OR REPLACE FUNCTION public.increment_metric(metric_key TEXT)
RETURNS VOID AS $$
BEGIN
  INSERT INTO public.system_metrics (key, value, updated_at)
  VALUES (metric_key, 1, NOW())
  ON CONFLICT (key)
  DO UPDATE SET 
    value = public.system_metrics.value + 1,
    updated_at = NOW();
END;
$$ LANGUAGE plpgsql SECURITY DEFINER;

-- 2. Atomic Rate Limiting (Check and Increment)
-- Returns true if allowed, false if limited
CREATE OR REPLACE FUNCTION public.check_and_increment_rate_limit(
  target_ip TEXT, 
  target_tier TEXT, 
  max_count INTEGER, 
  window_ms INTEGER
)
RETURNS TABLE (
  allowed BOOLEAN,
  current_count INTEGER,
  retry_after_seconds INTEGER
) AS $$
DECLARE
  current_window_start TIMESTAMPTZ;
  existing_count INTEGER;
  now_ms TIMESTAMPTZ := NOW();
  window_start_limit TIMESTAMPTZ := now_ms - (window_ms || ' milliseconds')::INTERVAL;
BEGIN
  -- Cleanup old entries for this IP/tier (optional, or rely on window check)
  
  SELECT window_start, count INTO current_window_start, existing_count
  FROM public.rate_limits
  WHERE ip = target_ip AND tier = target_tier
  FOR UPDATE; -- Lock for atomicity

  IF NOT FOUND OR current_window_start < window_start_limit THEN
    -- New window or first request
    INSERT INTO public.rate_limits (ip, tier, count, window_start)
    VALUES (target_ip, target_tier, 1, now_ms)
    ON CONFLICT (ip, tier) DO UPDATE
    SET count = 1, window_start = now_ms;
    
    RETURN QUERY SELECT TRUE, 1, 0;
  ELSIF existing_count >= max_count THEN
    -- Limited
    RETURN QUERY SELECT 
      FALSE, 
      existing_count, 
      CEIL(EXTRACT(EPOCH FROM (current_window_start + (window_ms || ' milliseconds')::INTERVAL - now_ms)))::INTEGER;
  ELSE
    -- Increment
    UPDATE public.rate_limits
    SET count = count + 1
    WHERE ip = target_ip AND tier = target_tier;
    
    RETURN QUERY SELECT TRUE, existing_count + 1, 0;
  END IF;
END;
$$ LANGUAGE plpgsql SECURITY DEFINER;
