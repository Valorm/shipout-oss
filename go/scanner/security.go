package scanner

import (
	"fmt"
	"strings"
)

// CheckCORS tests for permissive CORS policies (informational, not access control)
func CheckCORS(ctx *ScanContext) []Finding {
	status, headers, _, err := ctx.Client.Do("OPTIONS", ctx.Target, map[string]string{
		"Origin":                        "https://evil.example.com",
		"Access-Control-Request-Method": "GET",
	})
	if err != nil || status == 0 {
		// Fall back to GET with Origin header
		_, headers, _, err = ctx.Client.Do("GET", ctx.Target, map[string]string{
			"Origin": "https://evil.example.com",
		})
		if err != nil {
			return nil
		}
	}

	acao := headers.Get("Access-Control-Allow-Origin")
	if acao == "*" || acao == "https://evil.example.com" {
		return []Finding{{
			Type:        "cors_test",
			Description: fmt.Sprintf("Permissive CORS policy: Access-Control-Allow-Origin is '%s'", acao),
			Severity:    SeverityInfo,
			Endpoint:    ctx.Target,
			Remediation: "Restrict CORS to your specific frontend origins. CORS is not access control; real protection comes from authentication.",
			Agent:       "WebSecurityAgent",
		}}
	}
	return nil
}

// CheckCookies flags cookies missing security flags
func CheckCookies(ctx *ScanContext) []Finding {
	_, headers, _, err := ctx.Client.Get(ctx.Target)
	if err != nil {
		return nil
	}

	cookies := headers.Values("Set-Cookie")
	if len(cookies) == 0 {
		return nil
	}

	var findings []Finding
	for _, c := range cookies {
		lower := strings.ToLower(c)
		name := strings.Split(c, "=")[0]
		var issues []string
		if !strings.Contains(lower, "httponly") {
			issues = append(issues, "missing HttpOnly")
		}
		if !strings.Contains(lower, "secure") {
			issues = append(issues, "missing Secure")
		}
		if !strings.Contains(lower, "samesite") {
			issues = append(issues, "missing SameSite")
		}
		if len(issues) > 0 {
			findings = append(findings, Finding{
				Type:        "cookie_analysis",
				Description: fmt.Sprintf("Cookie '%s' has issues: %s", name, strings.Join(issues, ", ")),
				Severity:    SeverityLow,
				Endpoint:    ctx.Target,
				Remediation: "Set HttpOnly, Secure, and SameSite=Lax (or Strict) on all cookies.",
				Agent:       "WebSecurityAgent",
			})
		}
	}
	return findings
}

// stackTracePatterns indicate verbose error leakage
var stackTracePatterns = []string{
	"at Object.",
	"at async ",
	"Traceback (most recent call last)",
	".java:",
	"NullPointerException",
	"node_modules/",
	"webpack://",
}

// CheckStackTraces looks for verbose error messages in common endpoints
func CheckStackTraces(ctx *ScanContext) []Finding {
	testPaths := []string{"/boom", "/error", "/debug/error", "/api/error"}

	for _, p := range testPaths {
		url := strings.TrimSuffix(ctx.Target, "/") + p
		status, _, body, err := ctx.Client.Get(url)
		if err != nil || status == 404 {
			continue
		}
		for _, pattern := range stackTracePatterns {
			if strings.Contains(body, pattern) {
				return []Finding{{
					Type:        "data_leak",
					Description: fmt.Sprintf("Verbose error leak at %s (matched '%s')", url, pattern),
					Severity:    SeverityMedium,
					Endpoint:    url,
					Remediation: "Return generic error messages to clients. Log full stack traces server-side only.",
					Agent:       "DataLeakAgent",
				}}
			}
		}
	}
	return nil
}
