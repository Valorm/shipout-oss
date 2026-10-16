package scanner

import (
	"fmt"
	"strings"
)

// CheckTargetAlive verifies the target responds
func CheckTargetAlive(ctx *ScanContext) []Finding {
	status, _, _, err := ctx.Client.Get(ctx.Target)
	if err != nil {
		return []Finding{{
			Type:        "recon",
			Description: fmt.Sprintf("Target %s is not reachable: %v", ctx.Target, err),
			Severity:    SeverityHigh,
			Endpoint:    ctx.Target,
			Agent:       "ReconAgent",
		}}
	}

	return []Finding{{
		Type:        "recon",
		Description: fmt.Sprintf("Target %s is reachable (Status: %d).", ctx.Target, status),
		Severity:    SeverityInfo,
		Endpoint:    ctx.Target,
		Agent:       "ReconAgent",
	}}
}

// criticalHeaders are security headers that should be present
var criticalHeaders = []struct {
	name        string
	remediation string
}{
	{"x-frame-options", "Add X-Frame-Options: DENY to prevent clickjacking."},
	{"x-content-type-options", "Add X-Content-Type-Options: nosniff to prevent MIME sniffing."},
	{"strict-transport-security", "Add Strict-Transport-Security to enforce HTTPS."},
	{"content-security-policy", "Add a Content-Security-Policy to control resource loading."},
}

// CheckSecurityHeaders flags missing security headers
func CheckSecurityHeaders(ctx *ScanContext) []Finding {
	_, headers, _, err := ctx.Client.Get(ctx.Target)
	if err != nil {
		return nil
	}

	var findings []Finding
	for _, h := range criticalHeaders {
		if headers.Get(h.name) == "" {
			findings = append(findings, Finding{
				Type:        "header_analysis",
				Description: fmt.Sprintf("Missing critical security header: %s", h.name),
				Severity:    SeverityMedium,
				Endpoint:    ctx.Target,
				Remediation: h.remediation,
				Agent:       "WebSecurityAgent",
			})
		}
	}
	return findings
}

// sensitivePaths are common locations where secrets leak
var sensitivePaths = []string{
	"/.env",
	"/.env.local",
	"/.env.production",
	"/debug",
	"/.git/config",
	"/.git/HEAD",
	"/config.json",
	"/.aws/credentials",
	"/server.key",
	"/.npmrc",
	"/composer.json",
	"/package.json",
	"/web.config",
}

// CheckSensitiveFiles probes for exposed sensitive files
func CheckSensitiveFiles(ctx *ScanContext) []Finding {
	var findings []Finding
	var exposed []string

	for _, p := range sensitivePaths {
		url := strings.TrimSuffix(ctx.Target, "/") + p
		status, _, body, err := ctx.Client.Get(url)
		if err != nil || status != 200 {
			continue
		}
		// Avoid false positives from catch-all 200 pages
		if isCatchAll(body, p) {
			continue
		}
		exposed = append(exposed, p)
	}

	if len(exposed) > 0 {
		severity := SeverityHigh
		if len(exposed) == 1 && exposed[0] == "/package.json" {
			severity = SeverityLow
		}
		findings = append(findings, Finding{
			Type:        "sensitive_file_probe",
			Description: fmt.Sprintf("Exposed sensitive files: %s", strings.Join(exposed, ", ")),
			Severity:    severity,
			Endpoint:    ctx.Target,
			Evidence:    exposed,
			Remediation: "Remove these files from public access. Add them to .gitignore. Rotate any exposed secrets.",
			Agent:       "SecretsDiscoveryAgent",
		})
	} else {
		findings = append(findings, Finding{
			Type:        "sensitive_file_probe",
			Description: fmt.Sprintf("Probed %d common sensitive paths. None exposed.", len(sensitivePaths)),
			Severity:    SeverityInfo,
			Endpoint:    ctx.Target,
			Agent:       "SecretsDiscoveryAgent",
		})
	}

	return findings
}

// isCatchAll detects SPA-style catch-all pages that return 200 for everything
func isCatchAll(body, path string) bool {
	lower := strings.ToLower(body)
	// HTML responses for config-like paths are always catch-alls.
	// A real .env, .git/config, etc. never contains HTML.
	if strings.Contains(lower, "<html") || strings.Contains(lower, "<!doctype") {
		return true
	}
	return false
}
