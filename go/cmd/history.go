package cmd

import (
	"bufio"
	"fmt"
	"os"
	"os/exec"
	"regexp"
	"strings"
)

// Reuse secret patterns from scanner package by duplicating the key ones here
// (to avoid import cycle, since cmd imports scanner)
var historySecretPatterns = []struct {
	name    string
	pattern *regexp.Regexp
}{
	{"AWS Access Key", regexp.MustCompile(`AKIA[0-9A-Z]{16}`)},
	{"GitHub Token", regexp.MustCompile(`gh[opsu]_[a-zA-Z0-9]{36}`)},
	{"Slack Token", regexp.MustCompile(`xox[baprs]-[a-zA-Z0-9-]{10,}`)},
	{"Stripe Live Key", regexp.MustCompile(`sk_live_[a-zA-Z0-9]{24,}`)},
	{"Google API Key", regexp.MustCompile(`AIza[0-9A-Za-z_-]{35}`)},
	{"Private Key", regexp.MustCompile(`-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----`)},
	{"Hardcoded Secret", regexp.MustCompile(`(?i)(?:api[_-]?key|secret|token|password|passwd|pwd)\s*[:=]\s*["'][^"']{16,}["']`)},
}

// RunHistoryAudit scans git history for secrets
func RunHistoryAudit(path string) {
	// Check if this is a git repo
	gitDir := path + "/.git"
	if _, err := os.Stat(gitDir); os.IsNotExist(err) {
		fmt.Printf("Not a git repository: %s\n", path)
		os.Exit(1)
	}

	fmt.Printf("  Shipout Git History Audit\n  Scanning all commits for secrets...\n\n")

	// Get all diffs from history
	cmd := exec.Command("git", "-C", path, "log", "--all", "--full-history", "-p", "--no-merges")
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		fmt.Printf("Error: %v\n", err)
		os.Exit(1)
	}
	if err := cmd.Start(); err != nil {
		fmt.Printf("Error: %v\n", err)
		os.Exit(1)
	}

	type finding struct {
		commit  string
		pattern string
		match   string
	}
	var findings []finding
	currentCommit := ""
	seen := map[string]bool{}

	scanner := bufio.NewScanner(stdout)
	// Increase buffer for long lines
	scanner.Buffer(make([]byte, 1024*1024), 1024*1024)

	for scanner.Scan() {
		line := scanner.Text()
		// Track current commit
		if strings.HasPrefix(line, "commit ") {
			currentCommit = strings.TrimPrefix(line, "commit ")
			if len(currentCommit) > 8 {
				currentCommit = currentCommit[:8]
			}
			continue
		}
		// Only check added lines (not the +++ header)
		if !strings.HasPrefix(line, "+") || strings.HasPrefix(line, "+++") {
			continue
		}
		content := line[1:]
		for _, sp := range historySecretPatterns {
			matches := sp.pattern.FindAllString(content, -1)
			for _, m := range matches {
				redacted := m
				if len(m) > 12 {
					redacted = m[:8] + "...[redacted]"
				}
				key := currentCommit + sp.name + redacted
				if !seen[key] {
					seen[key] = true
					findings = append(findings, finding{currentCommit, sp.name, redacted})
				}
			}
		}
	}
	cmd.Wait()

	if len(findings) == 0 {
		fmt.Println("  No secrets found in git history.")
		return
	}

	fmt.Printf("  Found %d secret(s) in git history:\n\n", len(findings))
	for _, f := range findings {
		fmt.Printf("  [CRITICAL] %s in commit %s\n", f.pattern, f.commit)
		fmt.Printf("  Match: %s\n\n", f.match)
	}
	fmt.Println("  These secrets are in your git history forever.")
	fmt.Println("  Rotate them immediately, even if removed from current code.")
	os.Exit(1)
}
