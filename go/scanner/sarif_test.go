package scanner

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestToSARIF(t *testing.T) {
	result := &ScanResult{
		Target: "https://example.com",
		Findings: []Finding{
			{
				Type:        "header_analysis",
				Description: "Missing critical security header: x-frame-options",
				Severity:    SeverityMedium,
				Endpoint:    "https://example.com",
				Remediation: "Add X-Frame-Options: DENY",
			},
			{
				Type:        "xss_probe",
				Description: "Verified Reflected XSS",
				Severity:    SeverityHigh,
				Endpoint:    "https://example.com/search?q=test",
			},
		},
	}

	output, err := result.ToSARIF("0.4.0")
	if err != nil {
		t.Fatalf("ToSARIF failed: %v", err)
	}

	// Must be valid JSON
	var parsed map[string]interface{}
	if err := json.Unmarshal([]byte(output), &parsed); err != nil {
		t.Fatalf("SARIF output is not valid JSON: %v", err)
	}

	// Check version
	if parsed["version"] != "2.1.0" {
		t.Errorf("version = %v, want 2.1.0", parsed["version"])
	}

	// Check runs
	runs, ok := parsed["runs"].([]interface{})
	if !ok || len(runs) != 1 {
		t.Fatalf("runs should have 1 entry")
	}

	run := runs[0].(map[string]interface{})
	tool := run["tool"].(map[string]interface{})
	driver := tool["driver"].(map[string]interface{})
	if driver["name"] != "Shipout" {
		t.Errorf("driver name = %v, want Shipout", driver["name"])
	}

	// Check results
	results := run["results"].([]interface{})
	if len(results) != 2 {
		t.Errorf("results count = %d, want 2", len(results))
	}

	// Check severity mapping: HIGH -> error, MEDIUM -> warning
	for _, r := range results {
		res := r.(map[string]interface{})
		ruleID := res["ruleId"].(string)
		level := res["level"].(string)
		if ruleID == "xss_probe" && level != "error" {
			t.Errorf("xss_probe level = %s, want error", level)
		}
		if ruleID == "header_analysis" && level != "warning" {
			t.Errorf("header_analysis level = %s, want warning", level)
		}
	}

	// Output should contain the schema URL
	if !strings.Contains(output, "schemastore.org/sarif-2.1.0.json") {
		t.Error("SARIF output missing schema URL")
	}
}

func TestSeverityToSARIF(t *testing.T) {
	tests := []struct {
		severity Severity
		expected string
	}{
		{SeverityCritical, "error"},
		{SeverityHigh, "error"},
		{SeverityMedium, "warning"},
		{SeverityLow, "note"},
		{SeverityInfo, "note"},
	}
	for _, tt := range tests {
		if got := severityToSARIF(tt.severity); got != tt.expected {
			t.Errorf("severityToSARIF(%v) = %s, want %s", tt.severity, got, tt.expected)
		}
	}
}
