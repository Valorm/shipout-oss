# Shipout

AI-powered autonomous security scanner for modern web applications.

Shipout uses a team of specialized AI agents to perform reconnaissance, expand the attack surface, test vulnerabilities, and verify findings — similar to how a human security researcher investigates a target.

Unlike traditional scanners that run isolated checks, Shipout performs multi-step investigations to uncover deeper security issues.

## Quick Start

Run your first scan:

```bash
shipout scan https://example.com
```

Example output:

```
Shipout Autonomous Scan
Target: https://example.com

Reconnaissance
✓ http_probe
✓ robots_explorer
✓ sitemap_analyzer

Surface Expansion
✓ endpoint_discovery
✓ parameter_fuzzer

Vulnerability Analysis
✓ xss_probe
✓ sqli_probe
✓ open_redirect_probe

Verification
✓ verify_agent

No confirmed vulnerabilities found.
```

## Installation

Install globally with npm:

```bash
npm install -g shipout
```

Run a scan:

```bash
shipout scan https://target.com
```

## CLI Commands

| Command              | Description                              |
| -------------------- | ---------------------------------------- |
| `shipout scan <url>` | Run an autonomous security investigation |
| `shipout doctor`     | Check environment readiness              |
| `shipout --help`     | Show available commands                  |
| `shipout --version`  | Show installed version                   |

## How Shipout Works

Shipout uses an agent-driven investigation engine.

Each scan is coordinated by an orchestrator agent that delegates tasks to specialized agents:

```
OrchestratorAgent
│
├─ ReconAgent
├─ SurfaceExpansionAgent
├─ PayloadAgent
├─ WebSecurityAgent
└─ VerifyAgent
```

These agents dynamically select scanning tools based on discovered attack surfaces.

## Architecture

```
CLI
 ↓
Scan Engine
 ↓
AI Agents
 ↓
Tools
 ↓
Results
```

Shipout's core engine lives in the `core/` directory and is shared by both the CLI and the cloud platform.

## Example Investigation Flow

```
Target Discovery
 ↓
Endpoint Mapping
 ↓
Parameter Discovery
 ↓
Payload Testing
 ↓
Vulnerability Verification
```

This allows Shipout to detect issues that single-pass scanners may miss.

## Project Structure

```
apps/
  cli/          CLI interface

core/
  agents/       AI investigation agents
  tools/        scanning tools
  engine/       scan orchestration logic

packages/
  shared/       shared utilities

tests/          unit tests
```

## Contributing

Contributions are welcome.

1. Fork the repository
2. Create a feature branch
3. Submit a pull request

## Security

If you discover a security issue in Shipout, please report it privately instead of opening a public issue.

Contact: [security@valorm.xyz](mailto:security@valorm.xyz)

## License

MIT License

## Status

Shipout is currently in early development and evolving rapidly.

## Valorm Technologies

Shipout is developed by Valorm Technologies.
