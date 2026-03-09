# Trust Boundaries

This document visualizes the strict security zones and trust boundaries within the Shipout platform.

## Architecture Zones

```text
[ Internet ]
      │
      ▼
=========================================================
ZONE A: Public Zone (Edge)
---------------------------------------------------------
Components: Cloudflare WAF, Bot Management, CDN
Trust Level: Untrusted
Rules: 
- Blocks volumetric DDoS.
- Drops malformed HTTP requests.
- Enforces TLS 1.3.
=========================================================
      │
      ▼
=========================================================
ZONE B: Gateway Zone (Public Compute)
---------------------------------------------------------
Components: API Gateway, Next.js Frontend
Trust Level: Low Trust
Rules:
- Frontend contains ZERO secrets.
- API Gateway validates ALL incoming payloads against schemas.
- Enforces global and per-tenant rate limits.
- No direct access to databases or workers.
=========================================================
      │
      ▼
=========================================================
ZONE C: Service Zone (Private Compute)
---------------------------------------------------------
Components: Auth Service, Scan Orchestrator, Job Queue, Report Service
Trust Level: High Trust
Rules:
- No inbound internet access.
- Services authenticate via mutual TLS (mTLS).
- Orchestrator manages state but NEVER executes scans.
- Queue acts as a buffer to prevent compute exhaustion.
=========================================================
      │
      ▼
=========================================================
ZONE E: Execution Zone (Untrusted Compute)
---------------------------------------------------------
Components: Ephemeral Scan Workers (Firecracker microVMs)
Trust Level: ZERO TRUST (Hostile)
Rules:
- Workers assume all input is malicious.
- Destroyed immediately after 1 execution (Ephemeral).
- Network egress is strictly filtered (No internal IPs, no metadata APIs).
- Cannot communicate with Zone C or Zone D directly.
- Uploads results via short-lived pre-signed URLs.
=========================================================
      │ (Pre-signed URL PUT)
      ▼
=========================================================
ZONE D: Secure Core (Air-Gapped Data)
---------------------------------------------------------
Components: Primary Database, Object Storage, Vault, Immutable Logs
Trust Level: Absolute Trust
Rules:
- Completely isolated from the internet.
- Accessible only from Zone C (and specific pre-signed PUTs from Zone E).
- Enforces Row-Level Security (RLS).
- Logs are append-only and immutable (WORM).
=========================================================
```

## Security Guarantees

1. **Frontend Compromise**: If the Next.js UI is compromised, the attacker gains no secrets and cannot access the database.
2. **Worker Escape**: If a malicious payload breaks out of the scanner, it is trapped in a Firecracker microVM with no internal network access and is destroyed within 300 seconds.
3. **DDoS Resilience**: The Job Queue absorbs traffic spikes. If the queue fills up, the API Gateway sheds load (HTTP 429) before internal services crash.
