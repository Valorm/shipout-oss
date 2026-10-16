package main

import (
	"fmt"
	"os"

	"github.com/valorm/shipout/cmd"
)

const version = "0.3.0"

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
			fmt.Println("Usage: shipout scan <url>")
			os.Exit(1)
		}
		cmd.RunScan(os.Args[2])

	case "fix":
		if len(os.Args) < 3 {
			fmt.Println("Error: fix requires a target URL.")
			fmt.Println("Usage: shipout fix <url>")
			os.Exit(1)
		}
		cmd.RunFix(os.Args[2])

	case "init":
		cmd.RunInit()

	case "--version", "-v", "version":
		fmt.Printf("shipout v%s\n", version)

	case "--help", "-h", "help":
		printHelp()

	default:
		// Bare URL = scan it
		if len(command) > 4 && (command[:4] == "http") {
			cmd.RunScan(command)
			return
		}
		fmt.Printf("Unknown command: %s\n\n", command)
		printHelp()
		os.Exit(1)
	}
}

func printHelp() {
	fmt.Printf(`Shipout — Ship secure apps (v%s)

Usage:
  shipout scan <url>   Run a security scan
  shipout fix <url>    Scan and generate fix files
  shipout init         Scaffold Shipout into this project
  shipout --version    Show version
  shipout --help       Show this message

No API key required. Deterministic checks only.
`, version)
}
