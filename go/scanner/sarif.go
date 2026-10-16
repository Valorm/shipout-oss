package scanner

import (
	"encoding/json"
	"fmt"
)

// SARIF 2.1.0 output for GitHub code scanning integration

type sarifReport struct {
	Version string     `json:"version"`
	Schema  string     `json:"$schema"`
	Runs    []sarifRun `json:"runs"`
}

type sarifRun struct {
	Tool    sarifTool     `json:"tool"`
	Results []sarifResult `json:"results"`
}

type sarifTool struct {
	Driver sarifDriver `json:"driver"`
}

type sarifDriver struct {
	Name    string      `json:"name"`
	Version string      `json:"version"`
	Rules   []sarifRule `json:"rules"`
}

type sarifRule struct {
	ID               string `json:"id"`
	Name             string `json:"name"`
	ShortDescription sarifText `json:"shortDescription"`
	FullDescription  sarifText `json:"fullDescription"`
	DefaultSeverity  string    `json:"defaultConfigurationLevel,omitempty"`
}

type sarifText struct {
	Text string `json:"text"`
}

type sarifResult struct {
	RuleID    string          `json:"ruleId"`
	Level     string          `json:"level"`
	Message   sarifText       `json:"message"`
	Locations []sarifLocation `json:"locations"`
}

type sarifLocation struct {
	PhysicalLocation sarifPhysical `json:"physicalLocation"`
}

type sarifPhysical struct {
	ArtifactLocation sarifArtifact `json:"artifactLocation"`
}

type sarifArtifact struct {
	URI string `json:"uri"`
}

// severityToSARIF maps Shipout severities to SARIF levels
func severityToSARIF(s Severity) string {
	switch s {
	case SeverityCritical, SeverityHigh:
		return "error"
	case SeverityMedium:
		return "warning"
	case SeverityLow, SeverityInfo:
		return "note"
	default:
		return "note"
	}
}

// ToSARIF converts a ScanResult to SARIF 2.1.0 JSON
func (r *ScanResult) ToSARIF(version string) (string, error) {
	// Collect unique rules
	ruleMap := map[string]Finding{}
	for _, f := range r.Findings {
		if _, ok := ruleMap[f.Type]; !ok {
			ruleMap[f.Type] = f
		}
	}

	var rules []sarifRule
	for _, f := range ruleMap {
		rules = append(rules, sarifRule{
			ID:               f.Type,
			Name:             f.Type,
			ShortDescription: sarifText{Text: f.Description},
			FullDescription:  sarifText{Text: f.Remediation},
		})
	}

	var results []sarifResult
	for _, f := range r.Findings {
		results = append(results, sarifResult{
			RuleID:  f.Type,
			Level:   severityToSARIF(f.Severity),
			Message: sarifText{Text: f.Description},
			Locations: []sarifLocation{
				{
					PhysicalLocation: sarifPhysical{
						ArtifactLocation: sarifArtifact{URI: f.Endpoint},
					},
				},
			},
		})
	}

	report := sarifReport{
		Version: "2.1.0",
		Schema:  "https://json.schemastore.org/sarif-2.1.0.json",
		Runs: []sarifRun{
			{
				Tool: sarifTool{
					Driver: sarifDriver{
						Name:    "Shipout",
						Version: version,
						Rules:   rules,
					},
				},
				Results: results,
			},
		},
	}

	data, err := json.MarshalIndent(report, "", "  ")
	if err != nil {
		return "", fmt.Errorf("failed to marshal SARIF: %w", err)
	}
	return string(data), nil
}
