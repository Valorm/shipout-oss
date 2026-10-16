package cmd

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"

	"github.com/valorm/shipout/fixer"
	"github.com/valorm/shipout/scanner"
)

// RunReview scans JS/TS source under path for reliability issues that
// cannot be probed over the network (currently: HTTP calls without
// timeouts). With fix=true it also generates fix files.
func RunReview(path string, fix bool) {
	abs, err := filepath.Abs(path)
	if err != nil {
		fmt.Printf("Error: %v\n", err)
		os.Exit(1)
	}
	if st, err := os.Stat(abs); err != nil || !st.IsDir() {
		fmt.Printf("Error: %q is not a directory.\n", path)
		os.Exit(1)
	}

	findings, files := scanner.CheckTimeouts(abs)

	fmt.Printf("\n  Shipout Source Review\n  Path: %s\n  Files scanned: %d\n\n", abs, files)

	if len(findings) == 0 {
		fmt.Println("  No issues found. Every outbound request has a timeout.")
		return
	}

	bySeverity := map[scanner.Severity][]scanner.Finding{}
	for _, f := range findings {
		bySeverity[f.Severity] = append(bySeverity[f.Severity], f)
	}

	order := []scanner.Severity{
		scanner.SeverityCritical,
		scanner.SeverityHigh,
		scanner.SeverityMedium,
		scanner.SeverityLow,
		scanner.SeverityInfo,
	}

	actionable := 0
	for _, sev := range order {
		fs := bySeverity[sev]
		sort.Slice(fs, func(i, j int) bool {
			return fs[i].Endpoint < fs[j].Endpoint
		})
		for _, f := range fs {
			if sev != scanner.SeverityInfo {
				actionable++
			}
			printFinding(f)
		}
	}

	fmt.Printf("\n----------------------------------------\n")
	fmt.Printf("Files scanned: %d\n", files)
	fmt.Printf("Findings: %d (%d actionable)\n", len(findings), actionable)

	if fix && actionable > 0 {
		var actionableFindings []scanner.Finding
		for _, f := range findings {
			if f.Severity != scanner.SeverityInfo {
				actionableFindings = append(actionableFindings, f)
			}
		}
		fw := fixer.DetectFramework(abs)
		fmt.Printf("Detected framework: %s\n", fw)
		fixes := fixer.Generate(actionableFindings, fw)
		if len(fixes) == 0 {
			fmt.Println("No automatic fixes available for these findings.")
		} else {
			outDir := filepath.Join(abs, "shipout-fixes")
			written, err := fixer.Write(fixes, outDir)
			if err != nil {
				fmt.Printf("Error writing fixes: %v\n", err)
				os.Exit(1)
			}
			fmt.Printf("\nGenerated %d fix file(s) in ./shipout-fixes/:\n", len(fixes))
			for _, w := range written {
				fmt.Printf("   - %s\n", w)
			}
			fmt.Println("\nReview each file, adapt to your codebase, then delete the directory.")
		}
	} else if actionable > 0 {
		fmt.Println("\nRun 'shipout review --fix' to generate fix files.")
	}

	for _, sev := range order {
		if sev == scanner.SeverityInfo {
			continue
		}
		if len(bySeverity[sev]) > 0 {
			fmt.Printf("\nReview result: %d actionable finding(s).\n", actionable)
			os.Exit(1)
		}
	}
	fmt.Printf("\nReview result: clean.\n")
}
