package fixer

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/valorm/shipout/scanner"
)

func TestDetectFramework(t *testing.T) {
	tests := []struct {
		name     string
		pkgJSON  string
		expected Framework
	}{
		{"express", `{"dependencies":{"express":"^4.0.0"}}`, FrameworkExpress},
		{"nextjs", `{"dependencies":{"next":"^14.0.0"}}`, FrameworkNextJS},
		{"fastify", `{"dependencies":{"fastify":"^4.0.0"}}`, FrameworkFastify},
		{"koa", `{"dependencies":{"koa":"^2.0.0"}}`, FrameworkKoa},
		{"plain node", `{"dependencies":{"lodash":"^4.0.0"}}`, FrameworkNode},
		{"no package.json", "", FrameworkUnknown},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dir := t.TempDir()
			if tt.pkgJSON != "" {
				os.WriteFile(filepath.Join(dir, "package.json"), []byte(tt.pkgJSON), 0644)
			}
			if got := DetectFramework(dir); got != tt.expected {
				t.Errorf("DetectFramework() = %v, want %v", got, tt.expected)
			}
		})
	}
}

func TestGenerateHeadersFix(t *testing.T) {
	findings := []scanner.Finding{
		{Type: "header_analysis", Description: "Missing critical security header: x-frame-options", Severity: scanner.SeverityMedium},
	}

	fixes := Generate(findings, FrameworkExpress)
	if len(fixes) != 1 {
		t.Fatalf("Generate() returned %d fixes, want 1", len(fixes))
	}
	if fixes[0].Filename != "security-headers.js" {
		t.Errorf("Filename = %q, want security-headers.js", fixes[0].Filename)
	}
}

func TestGenerateEnvFix(t *testing.T) {
	findings := []scanner.Finding{
		{
			Type:        "sensitive_file_probe",
			Description: "Exposed sensitive files",
			Severity:    scanner.SeverityHigh,
			Evidence:    []string{"/.env"},
		},
	}

	fixes := Generate(findings, FrameworkExpress)
	// Should generate .gitignore.additions + ROTATE-SECRETS.md
	if len(fixes) != 2 {
		t.Fatalf("Generate() returned %d fixes, want 2", len(fixes))
	}
}

func TestGenerateXSSFix(t *testing.T) {
	findings := []scanner.Finding{
		{
			Type:        "xss_probe",
			Description: "Verified Reflected XSS",
			Severity:    scanner.SeverityHigh,
			Endpoint:    "https://example.com/search?q=test",
		},
	}

	fixes := Generate(findings, FrameworkExpress)
	if len(fixes) != 1 || fixes[0].Filename != "escape-html.js" {
		t.Errorf("Generate() should produce escape-html.js for XSS findings")
	}
}

func TestGenerateNoFixesForInfo(t *testing.T) {
	findings := []scanner.Finding{
		{Type: "cors_test", Description: "Permissive CORS", Severity: scanner.SeverityInfo},
	}

	// CORS is informational but we still generate a fix for it
	fixes := Generate(findings, FrameworkExpress)
	if len(fixes) != 1 {
		t.Errorf("Generate() should produce cors-config.js for CORS info findings")
	}
}

func TestGenerateTimeoutFix(t *testing.T) {
	findings := []scanner.Finding{
		{Type: "missing_timeout", Description: "HTTP request without a timeout", Severity: scanner.SeverityMedium},
	}

	for _, fw := range []Framework{FrameworkExpress, FrameworkNextJS, FrameworkFastify, FrameworkKoa, FrameworkNode} {
		fixes := Generate(findings, fw)
		if len(fixes) != 1 {
			t.Fatalf("[%s] Generate() returned %d fixes, want 1", fw, len(fixes))
		}
		if fixes[0].Filename != "timeout-helper.js" {
			t.Errorf("[%s] Filename = %q, want timeout-helper.js", fw, fixes[0].Filename)
		}
		if !contains(fixes[0].Content, "AbortSignal.timeout") {
			t.Errorf("[%s] fix content missing AbortSignal.timeout helper", fw)
		}
	}

	// Express gets server timeout wiring, Next.js does not
	expressFixes := Generate(findings, FrameworkExpress)
	if !contains(expressFixes[0].Content, "server.setTimeout") {
		t.Errorf("express fix missing server.setTimeout wiring")
	}
	nextFixes := Generate(findings, FrameworkNextJS)
	if !contains(nextFixes[0].Content, "route.js") {
		t.Errorf("nextjs fix missing route handler guidance")
	}

	// No timeout findings: no timeout fix file
	other := []scanner.Finding{
		{Type: "header_analysis", Description: "x", Severity: scanner.SeverityMedium},
	}
	for _, f := range Generate(other, FrameworkExpress) {
		if f.Filename == "timeout-helper.js" {
			t.Errorf("timeout fix generated without missing_timeout findings")
		}
	}
}

func contains(s, sub string) bool {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}
