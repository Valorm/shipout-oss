package scanner

import (
	"fmt"
	"regexp"
	"strings"
)

// PII patterns
var (
	emailPattern = regexp.MustCompile(`[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}`)
	// International phone: +233..., (233)..., 233-..., or long digit sequences
	phonePattern = regexp.MustCompile(`(?:\+?1[-.\s]?)?\(?[0-9]{3}\)?[-.\s]?[0-9]{3}[-.\s]?[0-9]{4}`)
	// Ghana phone: 02x, 03x, 05x followed by 7 digits
	ghanaPhonePattern = regexp.MustCompile(`\b0[235][0-9]{8}\b`)
)

// Common API endpoints that might leak PII
var piiEndpoints = []string{
	"/api/users",
	"/api/user",
	"/api/profile",
	"/api/customers",
	"/api/members",
	"/api/accounts",
	"/api/contacts",
	"/users",
	"/api/v1/users",
	"/api/v1/user",
}

// CheckPIILeakage probes API endpoints for PII in unauthenticated responses
func CheckPIILeakage(ctx *ScanContext) []Finding {
	var findings []Finding

	for _, endpoint := range piiEndpoints {
		url := strings.TrimSuffix(ctx.Target, "/") + endpoint
		status, headers, body, err := ctx.Client.Get(url)
		if err != nil || status != 200 {
			continue
		}

		// Only check JSON responses
		contentType := headers.Get("Content-Type")
		if !strings.Contains(contentType, "json") && !strings.HasPrefix(strings.TrimSpace(body), "{") && !strings.HasPrefix(strings.TrimSpace(body), "[") {
			continue
		}

		var piiTypes []string
		emails := emailPattern.FindAllString(body, -1)
		if len(emails) > 0 {
			// Filter out obvious non-PII (example.com, test domains)
			real := []string{}
			for _, e := range emails {
				lower := strings.ToLower(e)
				if !strings.Contains(lower, "example.com") && !strings.Contains(lower, "test.com") && !strings.Contains(lower, "@example") {
					real = append(real, e)
				}
			}
			if len(real) > 0 {
				piiTypes = append(piiTypes, fmt.Sprintf("%d email address(es)", len(real)))
			}
		}

		phones := phonePattern.FindAllString(body, -1)
		ghanaPhones := ghanaPhonePattern.FindAllString(body, -1)
		totalPhones := len(phones) + len(ghanaPhones)
		if totalPhones > 0 {
			piiTypes = append(piiTypes, fmt.Sprintf("%d phone number(s)", totalPhones))
		}

		if len(piiTypes) > 0 {
			findings = append(findings, Finding{
				Type:        "pii_leakage",
				Severity:    SeverityHigh,
				Description: fmt.Sprintf("PII exposed in unauthenticated API response: %s", strings.Join(piiTypes, ", ")),
				Endpoint:    url,
				Evidence:    []string{fmt.Sprintf("Found %s without authentication", strings.Join(piiTypes, ", "))},
				Remediation: "Require authentication for this endpoint. Implement proper authorization checks. Consider whether this data should be exposed at all.",
			})
		}
	}

	return findings
}
