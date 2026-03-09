/**
 * Emergency Stop Policy (Kill Switch)
 * 
 * This policy is evaluated at the API Gateway and Orchestrator layers.
 * In a live incident, these flags are toggled via a secure internal 
 * configuration store (e.g., AWS AppConfig or Consul) to immediately 
 * halt malicious activity.
 */
export const EmergencyStopPolicy = {
  // Global kill switch - stops ALL new scans from being queued
  GLOBAL_SCAN_DISABLE: false,
  
  // Disable specific worker types if a vulnerability is found in a specific scanner
  DISABLED_WORKER_TYPES: [] as Array<'url' | 'repo'>,
  
  // Instantly drop traffic from specific regions at the edge
  BLOCKED_REGIONS: [] as string[],
  
  // Instantly drop traffic from specific ASNs or IPs
  BLOCKED_IPS: [] as string[],

  // If true, forces all active workers to terminate immediately
  TERMINATE_ACTIVE_WORKERS: false
} as const;

export type EmergencyStopConfig = typeof EmergencyStopPolicy;
