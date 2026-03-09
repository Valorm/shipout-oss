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
