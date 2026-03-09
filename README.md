# Shipout

Pre-launch security auditing platform for modern web applications.

## Product Direction: Agentic AI Security Investigator

Shipout is designed as an **agentic security investigator**, not a static checklist scanner.

Instead of:

- AI reads code and guesses vulnerabilities

Shipout uses:

- AI agent orchestrator
- deterministic security tools
- sandboxed execution workers
- risk analysis and human-readable reporting

In practice, the AI should behave like a junior security engineer using controlled tooling.

## High-Level Architecture

```text
User
↓
Scan Request
↓
Agent Orchestrator
↓
Tool Execution Layer
↓
Sandboxed Workers
↓
Findings
↓
AI Risk Analysis
↓
Security Report
```

### Core Model

- **AI decides what to test next**
- **Tools perform each test deterministically**

## Agent Orchestrator Responsibilities

The orchestrator is the investigation brain for each scan.

Responsibilities:

- understand the target
- plan the investigation sequence
- select and run relevant tools
- interpret outputs
- choose follow-up tests based on findings

Example reasoning path:

```text
/login discovered
↓
run brute-force protection checks
↓
no rate limiting detected
↓
classify as high account takeover risk
```

## Tool Execution Layer

The agent controls specialized security tooling, such as:

- **HTTP inspector**
  - security headers
  - cookie flags
  - CORS configuration
  - TLS behavior
- **Endpoint discovery**
  - `robots.txt`
  - `sitemap.xml`
  - hidden/common routes
  - API endpoints
- **Rate-limit tester**
  - repeated requests to sensitive endpoints
  - response behavior analysis
- **Authentication tester**
  - brute-force resistance
  - bot protection checks
  - session handling checks
- **Secret detection**
  - token/key/credential exposure detection
- **Dependency analysis**
  - known vulnerable package detection

## Sandboxed Worker Requirements

Every scan runs in isolated compute with strict guardrails:

- no internal network access
- metadata IP ranges blocked
- memory and CPU constraints
- max runtime per scan
- max requests per scan

This prevents scanner abuse and lateral movement attempts.

## Investigation Loop

Each scan follows a context-aware loop:

```text
observe → decide → test → analyze → repeat
```

Example:

```text
discover endpoints
↓
detect login/auth surface
↓
test rate limiting and bot defenses
↓
evaluate account takeover risk
```

## Risk Analysis & Reporting

The AI layer should aggregate raw outputs into actionable risk statements.

Example grouping:

- Missing rate limiting
- No CAPTCHA/bot challenge
- Public login endpoint

Classified as:

- Category: Authentication Abuse / Account Takeover
- Severity: High

Final report should include:

- security score
- top prioritized risks
- detailed finding breakdown
- concrete remediation guidance

Example output format:

- **Risk**: High
- **Category**: Authentication Abuse
- **Issue**: Login endpoint allows unlimited attempts
- **Impact**: Attackers can brute-force user accounts
- **Recommendation**: Add rate limiting and CAPTCHA/bot protections

## Why This Matters

Traditional scanners run a fixed checklist. An agentic investigator adapts to context.

Examples:

- GraphQL detected → run GraphQL-specific abuse tests
- File upload detected → run upload abuse checks
- Auth endpoints detected → prioritize brute-force/session tests

This yields better signal, better prioritization, and clearer developer guidance.

## Architecture

Shipout follows a zero-trust, isolated execution model:

- API Edge (Next.js)
- Gateway Adapter
- Job Queue
- Ephemeral Workers (sandboxed)
- Policy-driven security controls
- Observability & incident response

See `MONOREPO_ARCHITECTURE.md` for full details.

## Core Principles

- Zero Trust Communication
- Ephemeral Execution
- No Credential Mounting
- Policy-Driven Security
- Defense in Depth

## Status

Early infrastructure deployment phase.

## Deployment Notes

For production deployments on Fly.io, you must set the `GEMINI_API_KEY` secret on both the API and consumer apps for AI-assisted analysis to function:

```bash
fly secrets set GEMINI_API_KEY=your_real_key_here --app shipout-api
fly secrets set GEMINI_API_KEY=your_real_key_here --app shipout-consumer
```

Worker reliability on Fly.io:

```bash
# Keep at least one worker VM running (prevents scan queue timeouts)
fly scale count 1 -a shipout-worker

# Resume apps if they were suspended
fly apps resume shipout-worker
fly apps resume shipout-consumer
```

The worker app (`workers/static-analysis-worker/fly.toml`) is intentionally configured without an `[http_service]` section because it is a background process, not an HTTP service. This avoids accidental auto-stop behavior for idle web traffic.
