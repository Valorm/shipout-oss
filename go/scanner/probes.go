package scanner

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/url"
	"strings"
)

// CheckXSS probes for reflected XSS in common parameters
func CheckXSS(ctx *ScanContext) []Finding {
	// First, discover forms and inputs from the homepage
	_, _, body, err := ctx.Client.Get(ctx.Target)
	if err != nil {
		return nil
	}

	// Find form actions and common search endpoints
	targets := discoverProbeTargets(ctx.Target, body)

	payload := "<script>alert('shipout')</script>"
	var findings []Finding

	for _, target := range targets {
		for _, param := range []string{"q", "query", "search", "s", "keyword"} {
			testURL := addParam(target, param, payload)
			_, _, respBody, err := ctx.Client.Get(testURL)
			if err != nil {
				continue
			}
			if strings.Contains(respBody, payload) {
				findings = append(findings, Finding{
					Type:        "xss_probe",
					Description: fmt.Sprintf("Verified Reflected XSS at %s via parameter '%s'", target, param),
					Severity:    SeverityHigh,
					Endpoint:    testURL,
					Evidence:    []string{fmt.Sprintf("Payload reflected unescaped: %s", payload)},
					Remediation: "Escape all user input before rendering in HTML. Use a templating engine with auto-escaping.",
					Agent:       "PayloadAgent",
				})
				break // One finding per target is enough
			}
		}
	}

	return findings
}

// discoverProbeTargets finds URLs worth probing for XSS
func discoverProbeTargets(base, body string) []string {
	targets := []string{base}
	lower := strings.ToLower(body)

	// Look for form actions
	for _, marker := range []string{`action="`, `action='`} {
		idx := 0
		for {
			pos := strings.Index(lower[idx:], marker)
			if pos == -1 {
				break
			}
			start := idx + pos + len(marker)
			end := strings.IndexAny(lower[start:], `"'`)
			if end == -1 {
				break
			}
			action := body[start : start+end]
			if action != "" && action != "#" {
				resolved := resolveURL(base, action)
				if resolved != "" && !contains(targets, resolved) {
					targets = append(targets, resolved)
				}
			}
			idx = start + end
		}
	}

	// Common search endpoints
	for _, p := range []string{"/search", "/query"} {
		u := strings.TrimSuffix(base, "/") + p
		if !contains(targets, u) {
			targets = append(targets, u)
		}
	}

	return targets
}

func addParam(base, key, value string) string {
	sep := "?"
	if strings.Contains(base, "?") {
		sep = "&"
	}
	return base + sep + key + "=" + url.QueryEscape(value)
}

func resolveURL(base, ref string) string {
	if strings.HasPrefix(ref, "http") {
		return ref
	}
	if strings.HasPrefix(ref, "/") {
		// Resolve against base origin
		if u, err := url.Parse(base); err == nil {
			return u.Scheme + "://" + u.Host + ref
		}
		return ""
	}
	return strings.TrimSuffix(base, "/") + "/" + ref
}

func contains(slice []string, s string) bool {
	for _, v := range slice {
		if v == s {
			return true
		}
	}
	return false
}

// CheckSupabase detects exposed Supabase credentials
func CheckSupabase(ctx *ScanContext) []Finding {
	_, _, body, err := ctx.Client.Get(ctx.Target)
	if err != nil {
		return nil
	}

	var findings []Finding

	// Look for Supabase project URLs
	if strings.Contains(body, ".supabase.co") {
		findings = append(findings, Finding{
			Type:        "supabase_detect",
			Description: "Supabase project URL detected in page. Verify RLS policies are enforced.",
			Severity:    SeverityInfo,
			Endpoint:    ctx.Target,
			Remediation: "Ensure Row Level Security is enabled on all tables. Test as two different users.",
			Agent:       "DataLeakAgent",
		})
	}

	// Look for JWTs and check for service_role
	for _, token := range extractJWTs(body) {
		claims := decodeJWTClaims(token)
		if claims == nil {
			continue
		}
		if role, ok := claims["role"].(string); ok && role == "service_role" {
			findings = append(findings, Finding{
				Type:        "supabase_detect",
				Description: "Exposed Supabase service_role key. This bypasses all RLS policies.",
				Severity:    SeverityCritical,
				Endpoint:    ctx.Target,
				Remediation: "Remove the service_role key from client-side code immediately. Rotate the key in Supabase dashboard. Use the anon key for frontend.",
				Agent:       "DataLeakAgent",
			})
			break
		}
	}

	return findings
}

// extractJWTs finds JWT-like strings in body
func extractJWTs(body string) []string {
	var tokens []string
	parts := strings.FieldsFunc(body, func(r rune) bool {
		return r == '"' || r == '\'' || r == ' ' || r == '\n' || r == '<' || r == '>'
	})
	for _, p := range parts {
		segments := strings.Split(p, ".")
		if len(segments) == 3 && len(p) > 50 {
			tokens = append(tokens, p)
		}
	}
	return tokens
}

// decodeJWTClaims decodes the payload of a JWT without verification
func decodeJWTClaims(token string) map[string]interface{} {
	segments := strings.Split(token, ".")
	if len(segments) != 3 {
		return nil
	}
	payload, err := base64.RawURLEncoding.DecodeString(segments[1])
	if err != nil {
		return nil
	}
	var claims map[string]interface{}
	if err := json.Unmarshal(payload, &claims); err != nil {
		return nil
	}
	return claims
}
