# Shipout

You built your app fast. Shipout makes sure you don't ship it with the doors open.

Shipout is a security scanner for people who build fast. Point it at your app and it checks for exposed secrets, missing security headers, XSS, open debug routes, and more. Every finding comes with a plain language explanation and a fix.

No API key. No signup. No runtime to install. Single binary.

## Download

Grab the binary for your platform from [Releases](https://github.com/Valorm/shipout-oss/releases/latest):

- Linux (x64)
- macOS (Intel and Apple Silicon)
- Windows (x64)

```bash
chmod +x shipout-linux-x64
./shipout-linux-x64 scan https://yourapp.com
```

## Commands

| Command                            | What it does                                        |
| ---------------------------------- | --------------------------------------------------- |
| `shipout scan <url>`               | Scan a target and report findings                   |
| `shipout scan <url> --format=sarif` | Scan and output SARIF 2.1.0 JSON for GitHub code scanning |
| `shipout audit [path]`          | Audit local dependencies for known vulnerabilities      |
| `shipout fix <url>`                | Scan and generate fix files for your framework      |
| `shipout init`                     | Scaffold Shipout config and CI workflow into a project |

### SARIF output

Use `--format=sarif` to get SARIF 2.1.0 JSON output. Pipe it to a file and upload it to GitHub code scanning to see findings as inline PR annotations:

```
shipout scan https://myapp.com --format=sarif > results.sarif
```

Severity mapping: CRITICAL and HIGH become `error`, MEDIUM becomes `warning`, LOW and INFO become `note`.

### Dependency audit

`shipout audit` scans your local `package-lock.json` (or `package.json`) against the OSV vulnerability database. No API key required.

```
$ shipout audit
  Shipout Dependency Audit
  Scanning 142 packages...

  [HIGH] lodash@4.17.20
  GHSA-4xc9-xhrj-v574: Prototype pollution in lodash
```

### Pre-commit hook

`shipout init` installs a `.git/hooks/pre-commit` hook that runs `shipout audit` before each commit. Commits are blocked if known vulnerabilities are found. Bypass with `git commit --no-verify`.

### Git history audit

`shipout audit --history` scans every commit in your git history for hardcoded secrets. Secrets in history are forever, even if removed from current code. Rotate any findings immediately.

### Ignoring findings

Create a `.shipoutignore` file in your project directory to suppress accepted risks or false positives. One rule per line:

```
# Ignore CORS on the API subdomain (intentional)
cors:api.example.com

# Accept the risk on missing headers, tracking in JIRA-123
header_analysis
```

The scan automatically applies these rules and reports how many findings were ignored.

## How it works

Shipout runs deterministic security checks. No AI, no cloud, no data leaves your machine except the HTTP requests to your target.

Checks include:
- Security headers (CSP, HSTS, X-Frame-Options, and more)
- Hardcoded secrets in JavaScript (AWS keys, GitHub tokens, Stripe keys, and more)
- Exposed sensitive files (`.env`, `.git/config`, debug routes)
- Reflected XSS probing
- CORS misconfiguration
- Cookie security flags
- Supabase service role key exposure
- Stack trace and error message leakage

`shipout fix` detects your framework (Express, Next.js, Fastify, Koa) and generates ready to use fix files.

## Responsible use

Only scan targets you own or have explicit permission to test. Unauthorized scanning may violate laws or terms of service in your jurisdiction. Shipout is a defensive tool for securing your own applications.

## Building from source

Requires Go 1.21+.

```bash
cd go
go build -o shipout .
./shipout scan https://yourapp.com
```

Run tests:

```bash
cd go
go test ./...
```

## License

MIT. See [LICENSE](LICENSE).
