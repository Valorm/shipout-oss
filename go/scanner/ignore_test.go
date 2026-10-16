package scanner

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLoadIgnoreFile(t *testing.T) {
	dir := t.TempDir()
	content := `# Ignore CORS on API subdomain
cors:api.example.com

# Ignore all header findings, accepted risk
header_analysis # tracking in JIRA-123
`
	os.WriteFile(filepath.Join(dir, ".shipoutignore"), []byte(content), 0644)

	rules := LoadIgnoreFile(dir)
	if len(rules) != 2 {
		t.Fatalf("expected 2 rules, got %d", len(rules))
	}
	if rules[0].Type != "cors" || rules[0].Endpoint != "api.example.com" {
		t.Errorf("rule 0 = %+v, want cors:api.example.com", rules[0])
	}
	if rules[1].Type != "header_analysis" || rules[1].Reason != "tracking in JIRA-123" {
		t.Errorf("rule 1 = %+v", rules[1])
	}
}

func TestLoadIgnoreFileMissing(t *testing.T) {
	rules := LoadIgnoreFile(t.TempDir())
	if len(rules) != 0 {
		t.Errorf("expected 0 rules for missing file, got %d", len(rules))
	}
}

func TestShouldIgnore(t *testing.T) {
	rules := []IgnoreRule{
		{Type: "cors", Endpoint: "api.example.com"},
		{Type: "header_analysis"},
	}

	tests := []struct {
		finding Finding
		ignored bool
	}{
		{Finding{Type: "cors", Endpoint: "https://api.example.com/data"}, true},
		{Finding{Type: "cors", Endpoint: "https://other.com/data"}, false},
		{Finding{Type: "header_analysis", Endpoint: "https://any.com"}, true},
		{Finding{Type: "xss_probe", Endpoint: "https://any.com"}, false},
	}
	for _, tt := range tests {
		if got := ShouldIgnore(tt.finding, rules); got != tt.ignored {
			t.Errorf("ShouldIgnore(%+v) = %v, want %v", tt.finding, got, tt.ignored)
		}
	}
}

func TestFilterFindings(t *testing.T) {
	findings := []Finding{
		{Type: "cors", Endpoint: "https://api.example.com"},
		{Type: "header_analysis", Endpoint: "https://example.com"},
		{Type: "xss_probe", Endpoint: "https://example.com/search"},
	}
	rules := []IgnoreRule{{Type: "cors"}}

	filtered, ignored := FilterFindings(findings, rules)
	if ignored != 1 {
		t.Errorf("ignored = %d, want 1", ignored)
	}
	if len(filtered) != 2 {
		t.Errorf("filtered count = %d, want 2", len(filtered))
	}
}
