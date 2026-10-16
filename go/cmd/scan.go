package cmd

import (
	"fmt"
	"os"
	"sort"
	"strings"

	"github.com/valorm/shipout/scanner"
)

// RunScan executes a security scan against the target
func RunScan(target string, format string) {
	result := scanner.Run(target)

	// Apply .shipoutignore rules from current directory
	rules := scanner.LoadIgnoreFile(".")
	if len(rules) > 0 {
		filtered, ignored := scanner.FilterFindings(result.Findings, rules)
		result.Findings = filtered
		if ignored > 0 {
			fmt.Printf("  Ignored %d finding(s) via .shipoutignore\n\n", ignored)
		}
	}

	if format == "sarif" {
		output, err := result.ToSARIF("0.9.0")
		if err != nil {
			fmt.Printf("Error generating SARIF: %v\n", err)
			os.Exit(1)
		}
		fmt.Println(output)
		// Exit 1 if critical findings for CI
		for _, f := range result.Findings {
			if f.Severity == scanner.SeverityCritical {
				os.Exit(1)
			}
		}
		return
	}

	fmt.Printf("\n  Shipout Security Scan\n  Target: %s\n\n", target)

	// Group by severity
	bySeverity := map[scanner.Severity][]scanner.Finding{}
	for _, f := range result.Findings {
		bySeverity[f.Severity] = append(bySeverity[f.Severity], f)
	}

	order := []scanner.Severity{
		scanner.SeverityCritical,
		scanner.SeverityHigh,
		scanner.SeverityMedium,
		scanner.SeverityLow,
		scanner.SeverityInfo,
	}

	vulnCount := 0
	for _, sev := range order {
		findings := bySeverity[sev]
		// Sort for stable output
		sort.Slice(findings, func(i, j int) bool {
			return findings[i].Description < findings[j].Description
		})
		for _, f := range findings {
			if sev != scanner.SeverityInfo {
				vulnCount++
			}
			printFinding(f)
		}
	}

	fmt.Printf("\n----------------------------------------\n")
	fmt.Printf("Duration: %.1fs\n", float64(result.DurationMs)/1000)
	fmt.Printf("Requests: %d\n", result.RequestCount)
	fmt.Printf("Vulnerabilities: %d\n", vulnCount)
	fmt.Printf("Informational: %d\n", len(bySeverity[scanner.SeverityInfo]))

	if len(bySeverity[scanner.SeverityCritical]) > 0 {
		fmt.Printf("\nScan result: CRITICAL vulnerabilities detected.\n")
		os.Exit(1)
	}
	fmt.Printf("\nScan result: No critical vulnerabilities detected.\n")
}

func printFinding(f scanner.Finding) {
	fmt.Printf("\n[%s] %s\n\n", f.Severity, f.Description)
	if f.Endpoint != "" {
		fmt.Printf("Endpoint:\n%s\n\n", f.Endpoint)
	}
	if len(f.Evidence) > 0 {
		fmt.Printf("Evidence:\n%s\n\n", strings.Join(f.Evidence, "\n"))
	}
	if f.Remediation != "" {
		fmt.Printf("Fix: %s\n\n", f.Remediation)
	}
	if f.Agent != "" {
		fmt.Printf("Agent:\n%s\n", f.Agent)
	}
	fmt.Printf("---\n")
}
