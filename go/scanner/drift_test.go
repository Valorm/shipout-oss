package scanner

import (
	"os"
	"path/filepath"
	"testing"
)

func TestCompareDrift(t *testing.T) {
	previous := []Finding{
		{Type: "header_analysis", Endpoint: "https://example.com", Severity: SeverityMedium},
		{Type: "cors", Endpoint: "https://example.com", Severity: SeverityInfo},
	}
	current := []Finding{
		{Type: "header_analysis", Endpoint: "https://example.com", Severity: SeverityMedium},
		{Type: "xss_probe", Endpoint: "https://example.com/search", Severity: SeverityHigh},
	}

	drift := CompareDrift(current, previous)

	if len(drift.New) != 1 || drift.New[0].Type != "xss_probe" {
		t.Errorf("New = %v, want 1 xss_probe", drift.New)
	}
	if len(drift.Fixed) != 1 || drift.Fixed[0].Type != "cors" {
		t.Errorf("Fixed = %v, want 1 cors", drift.Fixed)
	}
	if len(drift.Same) != 1 || drift.Same[0].Type != "header_analysis" {
		t.Errorf("Same = %v, want 1 header_analysis", drift.Same)
	}
}

func TestCompareDriftEmpty(t *testing.T) {
	drift := CompareDrift([]Finding{}, []Finding{})
	if len(drift.New) != 0 || len(drift.Fixed) != 0 || len(drift.Same) != 0 {
		t.Error("empty comparison should yield empty results")
	}
}

func TestSaveLoadBaseline(t *testing.T) {
	dir := t.TempDir()
	// Change to temp dir for the test
	oldWd, _ := os.Getwd()
	os.Chdir(dir)
	defer os.Chdir(oldWd)

	findings := []Finding{
		{Type: "xss_probe", Endpoint: "https://example.com", Severity: SeverityHigh},
	}
	if err := SaveBaseline(findings); err != nil {
		t.Fatalf("SaveBaseline failed: %v", err)
	}

	loaded, err := LoadBaseline()
	if err != nil {
		t.Fatalf("LoadBaseline failed: %v", err)
	}
	if len(loaded) != 1 || loaded[0].Type != "xss_probe" {
		t.Errorf("loaded = %v, want 1 xss_probe", loaded)
	}

	// Cleanup
	os.Remove(filepath.Join(dir, driftFile))
}
