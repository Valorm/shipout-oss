export const QueuePolicy = {
  MAX_RETRIES: 3,
  DEAD_LETTER_ENABLED: true,
  TIMEOUT_MS: 300000, // 5 minutes
  MAX_BATCH_SIZE: 10,
  VISIBILITY_TIMEOUT_SEC: 360,
  RATE_LIMIT_PER_SECOND: 50
} as const;

export type QueuePolicyType = typeof QueuePolicy;
