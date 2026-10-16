package main

import (
	"fmt"
	"net/url"
	"os"
	"strings"

	"github.com/valorm/shipout/cmd"
)

const version = "0.13.0"

func main() {
	if len(os.Args) < 2 {
		printHelp()
		os.Exit(1)
	}

	command := os.Args[1]

	switch command {
	case "scan":
		if len(os.Args) < 3 {
			fmt.Println("Error: scan requires a target URL.")
			fmt.Println("Usage: shipout scan <url> [--format=sarif]")
			os.Exit(1)
		}
		target := validateTarget(os.Args[2])
		format := ""
		for _, arg := range os.Args[3:] {
			if arg == "--format=sarif" {
				format = "sarif"
			}
		}
		cmd.RunScan(target, format)

	case "fix":
		if len(os.Args) < 3 {
			fmt.Println("Error: fix requires a target URL.")
			fmt.Println("Usage: shipout fix <url>")
			os.Exit(1)
		}
		target := validateTarget(os.Args[2])
		cmd.RunFix(target)

	case "init":
		cmd.RunInit()

	case "audit":
		path := "."
		history := false
		for _, arg := range os.Args[2:] {
			if arg == "--history" {
				history = true
			} else if !strings.HasPrefix(arg, "-") {
				path = arg
			}
		}
		if history {
			cmd.RunHistoryAudit(path)
		} else {
			cmd.RunAudit(path)
		}

	case "review":
		path := "."
		fix := false
		for _, arg := range os.Args[2:] {
			if arg == "--fix" {
				fix = true
			} else if !strings.HasPrefix(arg, "-") {
				path = arg
			}
		}
		cmd.RunReview(path, fix)

	case "--version", "-v", "version":
		fmt.Printf("shipout v%s\n", version)

	case "--help", "-h", "help":
		printHelp()

	default:
		// Bare URL = scan it
		if len(command) > 4 && (command[:4] == "http") {
			cmd.RunScan(validateTarget(command), "")
			return
		}
		fmt.Printf("Unknown command: %s\n\n", command)
		printHelp()
		os.Exit(1)
	}
}

// validateTarget ensures the target is a valid http(s) URL
func validateTarget(raw string) string {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		fmt.Println("Error: target URL cannot be empty.")
		os.Exit(1)
	}
	u, err := url.Parse(raw)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
		fmt.Printf("Error: %q is not a valid http(s) URL.\n", raw)
		os.Exit(1)
	}
	return strings.TrimSuffix(raw, "/")
}

func printHelp() {
	fmt.Printf(`Shipout — Ship secure apps (v%s)

Usage:
  shipout scan <url>   Run a security scan
  shipout fix <url>    Scan and generate fix files
  shipout init         Scaffold Shipout into this project
  shipout audit [path] Audit local dependencies for known vulnerabilities
  shipout review [path] [--fix]
                         Review source for reliability issues (timeouts)
  shipout audit --history
                         Scan git history for secrets
  shipout --version    Show version
  shipout --help       Show this message

No API key required. Deterministic checks only.
`, version)
}
