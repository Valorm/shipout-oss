package cmd

import (
	"fmt"
	"os"

	"github.com/valorm/shipout/fixer"
	"github.com/valorm/shipout/scanner"
)

// RunFix scans the target and generates fix files
func RunFix(target string) {
	fmt.Printf("Scanning for issues to fix...\n\n")

	result := scanner.Run(target)

	// Only generate fixes for non-informational findings
	var actionable []scanner.Finding
	for _, f := range result.Findings {
		if f.Severity != scanner.SeverityInfo {
			actionable = append(actionable, f)
		}
	}

	if len(actionable) == 0 {
		fmt.Println("No fixable issues found.")
		return
	}

	dir, err := os.Getwd()
	if err != nil {
		fmt.Printf("Error: %v\n", err)
		os.Exit(1)
	}

	fw := fixer.DetectFramework(dir)
	fmt.Printf("Detected framework: %s\n", fw)

	fixes := fixer.Generate(actionable, fw)
	if len(fixes) == 0 {
		fmt.Println("No automatic fixes available for these findings.")
		return
	}

	outDir := dir + "/shipout-fixes"
	written, err := fixer.Write(fixes, outDir)
	if err != nil {
		fmt.Printf("Error writing fixes: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("\nGenerated %d fix files in ./shipout-fixes/:\n", len(fixes))
	for _, w := range written {
		fmt.Printf("   - %s\n", w)
	}
	fmt.Println("\nReview each file, adapt to your codebase, then delete the directory.")
}
