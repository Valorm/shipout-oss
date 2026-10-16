package scanner

import (
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

// Source files scanned by the review command
var reviewExtensions = map[string]bool{
	".js": true, ".jsx": true, ".ts": true, ".tsx": true,
	".mjs": true, ".cjs": true, ".mts": true, ".cts": true,
}

// Directories never scanned by the review command
var reviewSkipDirs = map[string]bool{
	"node_modules": true, ".git": true, "dist": true, "build": true,
	"coverage": true, ".next": true, ".nuxt": true, "vendor": true,
	".turbo": true, "out": true,
}

var (
	fetchCallRe = regexp.MustCompile(`\bfetch\s*\(`)
	axiosCallRe = regexp.MustCompile(`\baxios\s*(?:\.\s*(?:create|get|post|put|patch|delete|head|options|request)\s*)?\(`)
	nodeCallRe  = regexp.MustCompile(`\bhttps?\s*\.\s*(?:request|get)\s*\(`)
	signalRe    = regexp.MustCompile(`\bsignal\b|AbortSignal`)
	timeoutRe   = regexp.MustCompile(`\btimeout\b`)
)

// CheckTimeouts scans JS/TS source under dir for outbound HTTP calls with
// no timeout. It returns the findings and the number of files scanned.
// Detection is syntactic and deterministic: a call with no options
// argument, or an inline options object with no timeout, is a definite
// finding. A call whose options are a variable Shipout cannot see into is
// reported as INFO ("could not verify") rather than guessed at.
func CheckTimeouts(dir string) ([]Finding, int) {
	var findings []Finding
	filesScanned := 0

	filepath.WalkDir(dir, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		if d.IsDir() {
			if reviewSkipDirs[d.Name()] {
				return filepath.SkipDir
			}
			return nil
		}
		if !reviewExtensions[strings.ToLower(filepath.Ext(path))] {
			return nil
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return nil
		}
		filesScanned++
		rel, _ := filepath.Rel(dir, path)
		findings = append(findings, scanFileForTimeouts(rel, string(data))...)
		return nil
	})

	return findings, filesScanned
}

// scanFileForTimeouts checks one source file for timeout-less HTTP calls
func scanFileForTimeouts(rel, src string) []Finding {
	var findings []Finding
	clean := sanitizeSource(src)
	origLines := strings.Split(src, "\n")
	hasSetTimeout := strings.Contains(clean, ".setTimeout(")

	check := func(re *regexp.Regexp, kind string) {
		for _, m := range re.FindAllStringIndex(clean, -1) {
			openIdx := m[1] - 1 // index of '('
			line := strings.Count(clean[:m[0]], "\n") + 1
			argsText := extractArgs(clean, openIdx)
			args := splitArgs(argsText)
			matched := clean[m[0]:m[1]]

			switch kind {
			case "fetch":
				findings = append(findings, classifyFetch(rel, line, args, snippet(origLines, line))...)
			case "axios":
				findings = append(findings, classifyAxios(rel, line, matched, args, snippet(origLines, line))...)
			case "node":
				findings = append(findings, classifyNode(rel, line, args, hasSetTimeout, snippet(origLines, line))...)
			}
		}
	}

	check(fetchCallRe, "fetch")
	check(axiosCallRe, "axios")
	check(nodeCallRe, "node")

	return findings
}

// classifyFetch evaluates a fetch() call site
func classifyFetch(rel string, line int, args []string, snip string) []Finding {
	loc := fmt.Sprintf("%s:%d", rel, line)
	if len(args) < 2 || strings.TrimSpace(args[1]) == "" {
		return []Finding{timeoutFinding(rel, loc, snip, SeverityMedium,
			"fetch() called with no options, so no timeout is set",
			"Pass { signal: AbortSignal.timeout(10000) } as the second argument. "+
				"Run 'shipout review --fix' to generate a ready to use helper.")}
	}
	opt := strings.TrimSpace(args[1])
	if signalRe.MatchString(opt) {
		return nil
	}
	if strings.HasPrefix(opt, "{") {
		return []Finding{timeoutFinding(rel, loc, snip, SeverityMedium,
			"fetch() options have no signal, so the request can hang forever",
			"Add signal: AbortSignal.timeout(10000) to the options object. "+
				"Run 'shipout review --fix' to generate a ready to use helper.")}
	}
	// Options are a variable or expression we cannot see into
	return []Finding{timeoutFinding(rel, loc, snip, SeverityInfo,
		"could not verify a timeout on this fetch() call (options are a variable)",
		"Confirm the options passed here include signal: AbortSignal.timeout(...). "+
			"If not, add one.")}
}

// classifyAxios evaluates an axios() call site
func classifyAxios(rel string, line int, matched string, args []string, snip string) []Finding {
	loc := fmt.Sprintf("%s:%d", rel, line)
	compact := strings.ReplaceAll(matched, " ", "")
	configIdx := 1
	if strings.Contains(compact, "create") || strings.HasPrefix(compact, "axios(") {
		configIdx = 0
	}
	what := "axios call"
	if strings.Contains(compact, "create") {
		what = "axios instance"
	}
	if len(args) <= configIdx || strings.TrimSpace(args[configIdx]) == "" {
		return []Finding{timeoutFinding(rel, loc, snip, SeverityMedium,
			what+" created with no timeout configured",
			"Set timeout: 10000 in the config. "+
				"Run 'shipout review --fix' to generate a ready to use helper.")}
	}
	cfg := strings.TrimSpace(args[configIdx])
	if timeoutRe.MatchString(cfg) {
		return nil
	}
	if strings.HasPrefix(cfg, "{") {
		return []Finding{timeoutFinding(rel, loc, snip, SeverityMedium,
			what+" config has no timeout, so requests can hang forever",
			"Add timeout: 10000 to the config object. "+
				"Run 'shipout review --fix' to generate a ready to use helper.")}
	}
	return []Finding{timeoutFinding(rel, loc, snip, SeverityInfo,
		"could not verify a timeout on this "+what+" (config is a variable)",
		"Confirm the config passed here includes timeout: .... If not, add one.")}
}

// classifyNode evaluates an http/https.request/get call site
func classifyNode(rel string, line int, args []string, hasSetTimeout bool, snip string) []Finding {
	loc := fmt.Sprintf("%s:%d", rel, line)
	// Drop a trailing callback argument from consideration
	opts := args
	if len(opts) > 1 {
		last := strings.TrimSpace(opts[len(opts)-1])
		if !strings.HasPrefix(last, "{") && !isStringLit(last) {
			opts = opts[:len(opts)-1]
		}
	}
	hasVariable := false
	for _, a := range opts {
		a = strings.TrimSpace(a)
		if a == "" {
			continue
		}
		switch {
		case strings.HasPrefix(a, "{"):
			if timeoutRe.MatchString(a) {
				return nil
			}
		case isStringLit(a):
			// URL string, not options
		default:
			hasVariable = true
		}
	}
	if hasVariable || hasSetTimeout {
		return []Finding{timeoutFinding(rel, loc, snip, SeverityInfo,
			"could not verify a timeout on this http request (timeout may be set via req.setTimeout)",
			"Confirm the request sets a timeout, either the timeout option or req.setTimeout(...).")}
	}
	return []Finding{timeoutFinding(rel, loc, snip, SeverityMedium,
		"http request with no timeout option and no req.setTimeout in this file",
		"Pass { timeout: 10000 } in the options, or call req.setTimeout(10000). "+
			"Run 'shipout review --fix' to generate a ready to use helper.")}
}

// isStringLit reports whether s looks like a quoted string literal
// (string contents are blanked by sanitizeSource, so "" remains)
func isStringLit(s string) bool {
	return strings.HasPrefix(s, "\"") || strings.HasPrefix(s, "'") || strings.HasPrefix(s, "`")
}

func timeoutFinding(rel, loc, snip string, sev Severity, what, remediation string) Finding {
	desc := fmt.Sprintf("HTTP request without a timeout — %s. %s.", loc, what)
	if sev == SeverityInfo {
		desc = fmt.Sprintf("Unverified request timeout — %s. %s.", loc, what)
	}
	ev := []string{loc}
	if snip != "" {
		ev = append(ev, snip)
	}
	return Finding{
		Type:        "missing_timeout",
		Severity:    sev,
		Description: desc,
		Endpoint:    loc,
		Evidence:    ev,
		Remediation: "If the other side is slow or hangs, this request hangs forever and can freeze your server. " + remediation,
	}
}

// snippet returns the original source line, trimmed for display
func snippet(lines []string, line int) string {
	if line < 1 || line > len(lines) {
		return ""
	}
	s := strings.TrimSpace(lines[line-1])
	if len(s) > 160 {
		s = s[:157] + "..."
	}
	return s
}

// extractArgs returns the raw text between the parens starting at openIdx
func extractArgs(src string, openIdx int) string {
	depth := 0
	for i := openIdx; i < len(src); i++ {
		switch src[i] {
		case '(':
			depth++
		case ')':
			depth--
			if depth == 0 {
				return src[openIdx+1 : i]
			}
		}
	}
	return ""
}

// splitArgs splits a raw argument list on top-level commas
func splitArgs(args string) []string {
	var parts []string
	depth := 0
	start := 0
	for i := 0; i < len(args); i++ {
		switch args[i] {
		case '(', '[', '{':
			depth++
		case ')', ']', '}':
			depth--
		case ',':
			if depth == 0 {
				parts = append(parts, args[start:i])
				start = i + 1
			}
		}
	}
	parts = append(parts, args[start:])
	return parts
}

// sanitizeSource removes block comments, line comments, and string literal
// contents so call site detection only sees real code. Line breaks are
// preserved so line numbers stay accurate.
func sanitizeSource(src string) string {
	var b strings.Builder
	b.Grow(len(src))
	inBlock := false
	inLine := false
	var inStr byte
	escaped := false

	for i := 0; i < len(src); i++ {
		c := src[i]
		switch {
		case inBlock:
			if c == '*' && i+1 < len(src) && src[i+1] == '/' {
				inBlock = false
				i++
				continue
			}
			if c == '\n' {
				b.WriteByte('\n')
			}
		case inLine:
			if c == '\n' {
				inLine = false
				b.WriteByte('\n')
			}
		case inStr != 0:
			switch {
			case escaped:
				escaped = false
			case c == '\\':
				escaped = true
			case c == inStr:
				inStr = 0
				b.WriteByte(c) // keep the closing quote
			case c == '\n':
				b.WriteByte('\n') // multiline template literal: keep line count
			}
		case c == '/' && i+1 < len(src) && src[i+1] == '*':
			inBlock = true
			i++
		case c == '/' && i+1 < len(src) && src[i+1] == '/':
			// Preserve :// so URLs are not treated as comments
			if i > 0 && src[i-1] == ':' {
				b.WriteByte(c)
			} else {
				inLine = true
				i++
			}
		case c == '"' || c == '\'' || c == '`':
			inStr = c
			b.WriteByte(c) // keep the opening quote so fetch("") still parses
		default:
			b.WriteByte(c)
		}
	}
	return b.String()
}
