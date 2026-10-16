package scanner

import (
	"encoding/json"
	"os"
)

const driftFile = ".shipout-last.json"

// DriftResult holds the comparison between two scans
type DriftResult struct {
	New   []Finding // In current scan, not in previous
	Fixed []Finding // In previous scan, not in current
	Same  []Finding // In both scans
}

// findingKey creates a stable identity for comparison
func findingKey(f Finding) string {
	return f.Type + "|" + f.Endpoint
}

// SaveBaseline writes findings to .shipout-last.json for future comparison
func SaveBaseline(findings []Finding) error {
	data, err := json.Marshal(findings)
	if err != nil {
		return err
	}
	return os.WriteFile(driftFile, data, 0644)
}

// LoadBaseline reads the previous scan's findings
func LoadBaseline() ([]Finding, error) {
	data, err := os.ReadFile(driftFile)
	if err != nil {
		return nil, err
	}
	var findings []Finding
	if err := json.Unmarshal(data, &findings); err != nil {
		return nil, err
	}
	return findings, nil
}

// CompareDrift compares current findings against the baseline
func CompareDrift(current, previous []Finding) DriftResult {
	prevKeys := map[string]Finding{}
	for _, f := range previous {
		prevKeys[findingKey(f)] = f
	}
	currKeys := map[string]Finding{}
	for _, f := range current {
		currKeys[findingKey(f)] = f
	}

	var result DriftResult
	for _, f := range current {
		if _, ok := prevKeys[findingKey(f)]; ok {
			result.Same = append(result.Same, f)
		} else {
			result.New = append(result.New, f)
		}
	}
	for _, f := range previous {
		if _, ok := currKeys[findingKey(f)]; !ok {
			result.Fixed = append(result.Fixed, f)
		}
	}
	return result
}
