# Shipout CLI

The official command-line interface for Shipout, the AI-powered autonomous security scanner.

## 🚀 Usage

Run a scan immediately:

```bash
npx shipout scan https://example.com
```

### Configuration (Required)

Shipout requires a **Gemini API key** to power its autonomous agent logic.

1. Get a free key at [Google AI Studio](https://aistudio.google.com/app/apikey).
2. Configure it via the setup command:
   ```bash
   npx shipout setup
   ```

Alternatively, you can provide the key via:
- `--api-key=YOUR_KEY` flag
- `GEMINI_API_KEY` environment variable
- `.env` file in your current directory

## Commands

- `shipout scan <target>`: Start an autonomous scan. Target can be a URL or a file containing multiple URLs.
- `shipout setup`: Enter your API key interactively.
- `shipout doctor`: Diagnose your local environment and connectivity.
- `shipout --concurrency=<num>`: Set parallel worker count (default: 5).
- `shipout --help`: View all available options.

## Features

- **Parallel Architecture**: High-speed concurrent scanning engine.
- **Autonomous Brain**: Uses Gemini models to decide which security tools to run and when.
- **Agent Architecture**: Features specialized agents for Recon, Surface Mapping, Secrets, and Verification.
- **Stealthy & Efficient**: Intelligent tool selection reduces noise while increasing coverage.
- **Human-Like Reasoning**: Not just a scanner — it investigates targets like a security researcher.
