export const ScanLimitsPolicy = {
  MAX_CONCURRENT_SCANS_PER_USER: 3,
  MAX_SCAN_DURATION_SECONDS: 300, // 5 minutes hard timeout
  MAX_REPO_SIZE_MB: 500,
  RATE_LIMIT_REQUESTS_PER_MINUTE: 60,
  MAX_PAYLOAD_SIZE_BYTES: 1048576, // 1MB
} as const;

export type ScanLimits = typeof ScanLimitsPolicy;
