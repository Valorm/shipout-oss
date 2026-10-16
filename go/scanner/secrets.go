package scanner

import (
	"fmt"
	"regexp"
)

// Hardcoded secret patterns for JavaScript scanning
var secretPatterns = []struct {
	name    string
	pattern *regexp.Regexp
}{
	{"AWS Access Key", regexp.MustCompile(`AKIA[0-9A-Z]{16}`)},
	{"GitHub Token", regexp.MustCompile(`gh[opsu]_[a-zA-Z0-9]{36}`)},
	{"GitHub App Token", regexp.MustCompile(`ghs_[a-zA-Z0-9]{36}`)},
	{"Slack Token", regexp.MustCompile(`xox[baprs]-[a-zA-Z0-9-]{10,}`)},
	{"Stripe Live Key", regexp.MustCompile(`sk_live_[a-zA-Z0-9]{24,}`)},
	{"Stripe Restricted Key", regexp.MustCompile(`rk_live_[a-zA-Z0-9]{24,}`)},
	{"Google API Key", regexp.MustCompile(`AIza[0-9A-Za-z_-]{35}`)},
	{"Private Key", regexp.MustCompile(`-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----`)},
	// Generic: variable named key/secret/token/password assigned a long string
	{"Hardcoded Secret", regexp.MustCompile(`(?i)(?:api[_-]?key|secret|token|password|passwd|pwd)\s*[:=]\s*["'][^"']{16,}["']`)},
}

// CheckHardcodedSecrets fetches JS files from the target and scans for hardcoded secrets
func CheckHardcodedSecrets(ctx *ScanContext) []Finding {
	var findings []Finding

	_, _, body, err := ctx.Client.Get(ctx.Target)
	if err != nil {
		return findings
	}

	jsURLs := extractJSURLs(body, ctx.Target)
	if len(jsURLs) == 0 {
		return findings
	}

	// Limit to first 10 JS files to avoid excessive requests
	if len(jsURLs) > 10 {
		jsURLs = jsURLs[:10]
	}

	for _, jsURL := range jsURLs {
		_, _, jsBody, err := ctx.Client.Get(jsURL)
		if err != nil {
			continue
		}

		for _, sp := range secretPatterns {
			matches := sp.pattern.FindAllString(jsBody, -1)
			if len(matches) > 0 {
				// Deduplicate with redaction
				seen := map[string]bool{}
				var unique []string
				for _, m := range matches {
					redacted := m
					if len(m) > 12 {
						redacted = m[:8] + "...[redacted]"
					}
					if !seen[redacted] {
						seen[redacted] = true
						unique = append(unique, redacted)
					}
				}
				findings = append(findings, Finding{
					Type:        "hardcoded_secret",
					Severity:    SeverityCritical,
					Description: fmt.Sprintf("%s found in %s", sp.name, jsURL),
					Endpoint:    jsURL,
					Evidence:    unique,
					Remediation: "Move secrets to environment variables or a secrets manager. Rotate any exposed credentials immediately.",
				})
			}
		}
	}

	return findings
}

// extractJSURLs finds <script src="..."> URLs in HTML
func extractJSURLs(html, base string) []string {
	var urls []string
	re := regexp.MustCompile(`<script[^>]+src=["']([^"']+)["']`)
	matches := re.FindAllStringSubmatch(html, -1)
	for _, m := range matches {
		if len(m) > 1 {
			resolved := resolveURL(base, m[1])
			if resolved != "" {
				urls = append(urls, resolved)
			}
		}
	}
	return urls
}
