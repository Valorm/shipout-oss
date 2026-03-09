export const RiskThresholdsPolicy = {
  CRITICAL_SCORE_MAX: 40,
  WARNING_SCORE_MAX: 79,
  PASSING_SCORE_MIN: 80,
  
  AUTO_BLOCK_ON_CRITICAL: true,
  REQUIRE_MANUAL_REVIEW_BELOW: 50,
  
  CATEGORIES: [
    'Network Security',
    'Data Exposure',
    'Authentication',
    'Dependency Risk',
    'Infrastructure Configuration'
  ]
} as const;

export type RiskThresholds = typeof RiskThresholdsPolicy;
