export const TrustBoundariesPolicy = {
  ZONES: {
    A_EDGE: 'Public Internet / Cloudflare',
    B_PUBLIC_COMPUTE: 'API Gateway / Frontend',
    C_PRIVATE_SERVICES: 'Auth / Orchestrator / Queue',
    D_SECURE_CORE: 'Database / Vault / Object Storage',
    E_UNTRUSTED_EXECUTION: 'Ephemeral Scan Workers'
  },
  RULES: [
    'Frontend contains ZERO secrets.',
    'API Gateway validates ALL requests before routing.',
    'Workers CANNOT access internal services or databases.',
    'Database is air-gapped from the public internet.',
    'Secrets are injected at runtime, never stored on disk.'
  ]
} as const;
