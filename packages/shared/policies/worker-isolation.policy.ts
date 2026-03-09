export const WorkerIsolationPolicy = {
  COMPUTE: 'Firecracker microVM',
  LIFECYCLE: 'Ephemeral (Destroyed after 1 execution)',
  NETWORK: {
    INGRESS: 'Blocked entirely',
    EGRESS: 'Restricted via NAT Gateway (No internal IPs)'
  },
  RESOURCES: {
    MAX_VCPU: 1,
    MAX_RAM_MB: 512,
    TIMEOUT_SECONDS: 300
  },
  STORAGE: 'Read-only rootfs, tmpfs for scratch space'
} as const;
