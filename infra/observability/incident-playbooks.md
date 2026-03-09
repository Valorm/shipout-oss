# Incident Response Playbooks

## 1. Worker Escape Attempt (Sev 1)
**Trigger**: `WorkerEscapeAttempt` alert fires (iptables drops to internal IPs).
**Action**:
1. Auto-quarantine the worker node via AWS Lambda.
2. Blackhole NAT Gateway egress for the affected subnet.
3. Page Security On-Call immediately.

## 2. Queue Backlog Critical (Sev 2)
**Trigger**: `QueueBacklogCritical` alert fires (>1000 pending jobs).
**Action**:
1. Verify if KEDA auto-scaling is functioning.
2. If volumetric attack, enable aggressive rate limiting at API Gateway.
3. Shed load by rejecting new scans with HTTP 429.
