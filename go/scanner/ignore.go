package scanner

import (
	"bufio"
	"os"
	"strings"
)

// IgnoreRule represents a single rule from .shipoutignore
type IgnoreRule struct {
	Type     string // Finding type to ignore (e.g., "header_analysis")
	Endpoint string // Optional endpoint pattern (substring match)
	Reason   string // Comment explaining why
}

// LoadIgnoreFile reads .shipoutignore from the given directory.
// Format (one rule per line):
//   # This is a comment
//   header_analysis              # ignore all header findings
//   cors:api.example.com         # ignore CORS for this endpoint
//   hardcoded_secret # we rotated it, tracking in JIRA-123
func LoadIgnoreFile(dir string) []IgnoreRule {
	var rules []IgnoreRule

	path := dir + "/.shipoutignore"
	file, err := os.Open(path)
	if err != nil {
		return rules
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		// Skip empty lines and comments
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		// Extract trailing comment as reason
		reason := ""
		if idx := strings.Index(line, "#"); idx >= 0 {
			reason = strings.TrimSpace(line[idx+1:])
			line = strings.TrimSpace(line[:idx])
		}
		if line == "" {
			continue
		}
		// Parse type:endpoint or just type
		rule := IgnoreRule{Reason: reason}
		if idx := strings.Index(line, ":"); idx >= 0 {
			rule.Type = strings.TrimSpace(line[:idx])
			rule.Endpoint = strings.TrimSpace(line[idx+1:])
		} else {
			rule.Type = line
		}
		if rule.Type != "" {
			rules = append(rules, rule)
		}
	}
	return rules
}

// ShouldIgnore checks if a finding matches any ignore rule
func ShouldIgnore(f Finding, rules []IgnoreRule) bool {
	for _, r := range rules {
		if r.Type != "" && r.Type != f.Type {
			continue
		}
		if r.Endpoint != "" && !strings.Contains(f.Endpoint, r.Endpoint) {
			continue
		}
		return true
	}
	return false
}

// FilterFindings removes findings that match ignore rules.
// Returns the filtered list and the count of ignored findings.
func FilterFindings(findings []Finding, rules []IgnoreRule) ([]Finding, int) {
	if len(rules) == 0 {
		return findings, 0
	}
	var kept []Finding
	ignored := 0
	for _, f := range findings {
		if ShouldIgnore(f, rules) {
			ignored++
		} else {
			kept = append(kept, f)
		}
	}
	return kept, ignored
}
