export const NetworkRulesPolicy = {
  ALLOWED_EGRESS_PORTS: [80, 443],
  BLOCKED_EGRESS_CIDRS: [
    '169.254.169.254/32', // AWS IMDSv1/v2
    '169.254.0.0/16',     // Generic Cloud IMDS/Link-local
    '10.0.0.0/8',         // Internal VPC
    '172.16.0.0/12',      // Internal VPC
    '192.168.0.0/16',     // Internal VPC
    '127.0.0.0/8',        // Localhost loopback
    '::1/128',            // IPv6 Localhost
    'fc00::/7',           // IPv6 Unique Local Addresses
    'fd00::/8',           // IPv6 Unique Local Addresses
    '0.0.0.0/8',          // Current network/Zero addresses
    '255.255.255.255/32'  // Broadcast
  ],
  REQUIRE_TLS_1_3: true,
  ENFORCE_HSTS: true,
} as const;

export type NetworkRules = typeof NetworkRulesPolicy;
