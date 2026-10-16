package cmd

import (
	"fmt"
	"os"
	"path/filepath"
)

// RunInit scaffolds Shipout into the current project
func RunInit() {
	dir, err := os.Getwd()
	if err != nil {
		fmt.Printf("Error: %v\n", err)
		os.Exit(1)
	}

	fmt.Println("Scaffolding Shipout security into this project...")

	// shipout.config.json
	configPath := filepath.Join(dir, "shipout.config.json")
	config := `{
  "target": "https://yourapp.com",
  "failOn": "high"
}
`
	if err := os.WriteFile(configPath, []byte(config), 0644); err != nil {
		fmt.Printf("Error writing config: %v\n", err)
		os.Exit(1)
	}
	fmt.Println("Created shipout.config.json")

	// GitHub Actions workflow
	workflowDir := filepath.Join(dir, ".github", "workflows")
	if err := os.MkdirAll(workflowDir, 0755); err != nil {
		fmt.Printf("Error creating workflow dir: %v\n", err)
		os.Exit(1)
	}

	workflow := `name: Shipout security scan

on:
  push:
    branches: [main]
  pull_request:
  workflow_dispatch:

jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Download Shipout
        run: |
          curl -sL -o shipout https://github.com/valorm/shipout/releases/latest/download/shipout-linux-x64
          chmod +x shipout

      - name: Run Shipout scan
        run: ./shipout scan "${{ vars.SHIPOUT_TARGET || 'https://example.com' }}" --fail-on=high
`
	workflowPath := filepath.Join(workflowDir, "shipout-scan.yml")
	if err := os.WriteFile(workflowPath, []byte(workflow), 0644); err != nil {
		fmt.Printf("Error writing workflow: %v\n", err)
		os.Exit(1)
	}
	fmt.Println("Created .github/workflows/shipout-scan.yml")

	// Pre-commit hook
	hookDir := filepath.Join(dir, ".git", "hooks")
	if _, err := os.Stat(hookDir); err == nil {
		hook := `#!/bin/sh
# Shipout pre-commit hook: audit dependencies before commit
# Installed by: shipout init
# Bypass with: git commit --no-verify

if command -v shipout >/dev/null 2>&1; then
  echo "Running Shipout dependency audit..."
  shipout audit .
  if [ $? -ne 0 ]; then
    echo ""
    echo "Shipout found vulnerabilities. Fix them or use --no-verify to bypass."
    exit 1
  fi
fi
`
		hookPath := filepath.Join(hookDir, "pre-commit")
		if err := os.WriteFile(hookPath, []byte(hook), 0755); err != nil {
			fmt.Printf("Warning: could not install pre-commit hook: %v\n", err)
		} else {
			fmt.Println("Created .git/hooks/pre-commit")
		}
	}

	fmt.Println("\nDone. Edit shipout.config.json with your target URL, then run: shipout scan <url>")
}
