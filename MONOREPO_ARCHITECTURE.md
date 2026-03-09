# Shipout Architecture Rules

This file locks in the strict architectural and security boundaries for the Shipout monorepo.

## 🔒 HARD RULES PER DIRECTORY

### 🧩 app/ — Next.js Application
- **Role**: Main UI and API Gateway using Next.js 15.
- **Allowed**: UI rendering, API Edge routes, session management.
- **Forbidden**: Heavy scanning logic (delegated to workers).

### 🚪 api-gateway/ — MOST IMPORTANT APP
- **Responsibilities**: Request validation, authentication verification, rate limiting, schema enforcement, audit logging, routing.
- **Forbidden**: Running scans, calculating reports, accessing workers directly.
- **Security Posture**: Zero-trust firewall. Traffic police only.

### 🔐 auth-service/
- **Responsibilities**: Login, token issuing, refresh rotation, MFA, device sessions.
- **Security Posture**: Single authority. No other service creates tokens.

### 🧠 scan-orchestrator/
- **Responsibilities**: Receive scan job, verify quota, assign worker, track status, handle retries, store lifecycle events.
- **Security Posture**: NEVER executes scans itself.

### ⚙️ workers/ — UNTRUSTED ZONE
- **Responsibilities**: Stateless, isolated, ephemeral execution. Destroyed after execution.
- **Security Posture**: Everything here is considered hostile execution. Input is malicious.
- **Network Rules**: Can reach internet and result upload endpoint. Cannot reach internal services, database, or metadata APIs.

### 🧾 report-service/
- **Responsibilities**: Security scoring, risk classification, report formatting, fix recommendations.
- **Security Posture**: Scoring is core intellectual property. Separated from execution.

### 💳 billing-service/
- **Responsibilities**: Scan quotas, usage tracking, payment validation, plan enforcement.
- **Security Posture**: Anti-abuse layer. Prevents attackers from abusing compute.

### 🧱 shared/
- **schemas/**: Single source of truth. No service invents its own format.
- **validation/**: ALL external input passes here first (e.g., SSRF protection).
- **security-utils/**: Reusable protections (IP blocking, token hashing). Never duplicate security logic.
- **policies/**: Policies ≠ code. Policies evolve without rewriting systems (e.g., scan limits, network rules).

### ☁️ infra/ — IMMUTABLE INFRASTRUCTURE
- **Responsibilities**: VPC rules, subnets, firewall configs, worker pools, secrets configuration.
- **observability/**: Logging config, metrics, alerts, dashboards. Security platforms MUST see attacks.
- **Security Posture**: No manual cloud edits allowed. Production changes ONLY via this folder.

## 🧠 FINAL ARCHITECTURE FLOW
User -> web-frontend -> api-gateway -> auth-service -> scan-orchestrator -> queue -> worker (isolated) -> report-service -> database -> frontend display.
