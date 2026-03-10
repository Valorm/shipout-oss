# Shipout

AI-powered autonomous security scanner for modern web applications.

Shipout uses a team of specialized AI agents to perform reconnaissance, expand the attack surface, test vulnerabilities, and verify findings — similar to how a human security researcher investigates a target.

Unlike traditional scanners that run isolated checks, Shipout performs multi-step investigations to uncover deeper security issues.

## 🚀 Quick Start

Run a scan immediately with `npx`:

```bash
npx shipout scan https://example.com
```

### First-Time Setup
Shipout requires an AI model to run autonomous scans. To configure your Gemini API key:

```bash
npx shipout setup
```

1. Create a free Gemini API key: [Google AI Studio](https://aistudio.google.com/app/apikey)
2. Run `shipout setup` and paste your key.

## Installation

Install globally with npm:

```bash
npm install -g shipout
```

Then run:

```bash
shipout scan https://target.com
```

## CLI Commands

| Command              | Description                               |
| -------------------- | ----------------------------------------- |
| `shipout scan <url>` | Run an autonomous security investigation  |
| `shipout setup`      | Interactive configuration for API keys    |
| `shipout doctor`     | Check environment readiness               |
| `shipout --help`     | Show available commands                   |
| `shipout --version`  | Show installed version                    |

## How Shipout Works

Shipout uses a high-performance **Parallel Architecture**.

Unlike traditional sequential scanners, Shipout coordinates multiple agents concurrently using an intelligent queue-driven engine:

```
                Orchestrator
                     │
        ┌────────────┴────────────┐
        │            │            │
   Recon Lane   Surface Lane   Payload Workers
        │            │            │
   [Endpoints] → [Queues]  → [Active Probes]
```

### Specialized Agents

- **ReconAgent**: Maps the initial surface and seeds the discovery queue.
- **SurfaceExpansionAgent**: Deep mines JavaScript, historical URLs, and subdomains.
- **PayloadAgent**: A pool of parallel workers that run active vulnerability probes (SQLi, XSS, SSRF).
- **Passive Agents**: Continuous data leak and secret discovery monitoring.

## 🛡️ Modern Web & SPA Scanning

Shipout is built for modern Single Page Applications (SPA). It goes beyond simple HTML crawling by:
- **JavaScript Route Discovery**: Support for Angular, React, and Vue routes.
- **API Endpoint Extraction**: Deep regex mining of `.js` files for internal API paths.
- **Parameter Discovery**: Fuzzing for hidden internal parameters.
- **Form Security Audit**: Real-time analysis of CSRF and insecure form submissions.

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
