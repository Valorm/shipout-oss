# Shipout

You built your app with AI in a weekend. Shipout makes sure you do not ship it with the doors open.

Shipout is a security scanner made for people who build fast. Point it at your app and it checks for the vulnerabilities that AI generated code tends to ship with: exposed API keys sitting in your JavaScript bundle, SQL injection, cross site scripting, open redirects, server side request forgery, and more. Every finding comes with a plain language explanation of how to fix it, not just a severity label.

## Quick start

```bash
npx shipout scan https://yourapp.com
```

Shipout needs a Gemini API key to run its investigation agents. Create a free one at [Google AI Studio](https://aistudio.google.com/app/apikey), then:

```bash
npx shipout setup
```

And paste your key when asked.

## Install it

```bash
npm install -g shipout
shipout scan https://yourapp.com
```

## Commands

| Command              | What it does                              |
| -------------------- | ----------------------------------------- |
| `shipout scan <url>` | Scan an app and report what to fix        |
| `shipout setup`      | Save your Gemini API key                  |
| `shipout doctor`     | Check that your environment is ready      |
| `shipout --help`     | Show all commands                         |
| `shipout --version`  | Show the installed version                |

Append `--json` to `scan` for machine readable output, or `--debug` to see everything the agents are doing.

## What a finding looks like

```
[HIGH] SQL Injection (Error-based) on parameter "id"

Endpoint:
https://yourapp.com/api/users

How to fix it:
Never build a database query by joining user input into the query string.
Use parameterized queries (prepared statements) so input is always treated
as data, never as code.
```

No security background required. If you can read the fix, you can apply it.

## How it works

Shipout sends a team of specialised AI agents at your app. One maps out every page, endpoint, and API route it can find, including routes hidden inside your JavaScript bundles. Others probe the app the way an attacker would, testing for injection flaws, leaked secrets, and misconfigurations. A final pass verifies each finding to cut down false alarms.

```
                Orchestrator
                     │
        ┌────────────┴────────────┐
        │            │            │
   Recon Lane   Surface Lane   Payload Workers
        │            │            │
   [Endpoints] → [Queues]  → [Active Probes]
```

The agents:

- **ReconAgent**: Maps the initial surface and seeds the discovery queue.
- **SurfaceExpansionAgent**: Digs through JavaScript, historical URLs, and subdomains.
- **PayloadAgent**: A pool of parallel workers running active vulnerability probes (SQLi, XSS, SSRF).
- **Passive agents**: Continuous data leak and secret discovery monitoring.

## Built for modern web apps

Shipout is made for single page applications, which is what most AI built apps are. It goes beyond simple HTML crawling:

- **JavaScript route discovery**: Follows Angular, React, and Vue routes.
- **API endpoint extraction**: Mines `.js` files for internal API paths.
- **Parameter discovery**: Probes for hidden parameters.
- **Form security audit**: Checks CSRF protection and insecure form submissions.
- **Secret scanning**: Finds exposed API keys (AWS, Stripe, Firebase, and others) in your bundles.

## Run it before every deploy

A GitHub Action is included in `.github/workflows/shipout-scan.yml`. Add your Gemini API key as a `GEMINI_API_KEY` secret and every push scans your staging URL before it reaches production.

## Project structure

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

Shipout is in early development and evolving rapidly. It is built by Valorm Technologies.
