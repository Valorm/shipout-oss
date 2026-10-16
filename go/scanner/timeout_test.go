package scanner

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// writeFixture creates dir/name with content and returns dir
func writeFixture(t *testing.T, name, content string) string {
	t.Helper()
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, name), []byte(content), 0644); err != nil {
		t.Fatal(err)
	}
	return dir
}

func findingsBySeverity(findings []Finding) map[Severity]int {
	m := map[Severity]int{}
	for _, f := range findings {
		m[f.Severity]++
	}
	return m
}

func TestCheckTimeoutsFetch(t *testing.T) {
	dir := writeFixture(t, "app.js", `
const res = await fetch("https://api.example.com/users");
`)
	findings, files := CheckTimeouts(dir)
	if files != 1 {
		t.Errorf("files scanned = %d, want 1", files)
	}
	bySev := findingsBySeverity(findings)
	if bySev[SeverityMedium] != 1 {
		t.Errorf("MEDIUM findings = %d, want 1 (%v)", bySev[SeverityMedium], findings)
	}
	if findings[0].Type != "missing_timeout" {
		t.Errorf("Type = %q, want missing_timeout", findings[0].Type)
	}
}

func TestCheckTimeoutsFetchInlineOptionsNoSignal(t *testing.T) {
	dir := writeFixture(t, "app.js", `
const res = await fetch(url, { method: "POST", body: data });
`)
	findings, _ := CheckTimeouts(dir)
	if findingsBySeverity(findings)[SeverityMedium] != 1 {
		t.Errorf("expected 1 MEDIUM finding, got %v", findings)
	}
}

func TestCheckTimeoutsFetchWithSignalClean(t *testing.T) {
	dir := writeFixture(t, "app.js", `
const res = await fetch(url, { signal: AbortSignal.timeout(10000) });
const r2 = await fetch(url, { signal: controller.signal });
`)
	findings, _ := CheckTimeouts(dir)
	if len(findings) != 0 {
		t.Errorf("expected no findings, got %v", findings)
	}
}

func TestCheckTimeoutsFetchVariableOptionsInfo(t *testing.T) {
	dir := writeFixture(t, "app.js", `
const res = await fetch(url, opts);
`)
	findings, _ := CheckTimeouts(dir)
	bySev := findingsBySeverity(findings)
	if bySev[SeverityInfo] != 1 || bySev[SeverityMedium] != 0 {
		t.Errorf("expected 1 INFO and 0 MEDIUM, got %v", findings)
	}
}

func TestCheckTimeoutsAxios(t *testing.T) {
	dir := writeFixture(t, "api.js", `
const api = axios.create({ baseURL: "https://api.example.com" });
const r = await axios.get("https://api.example.com/users");
const ok = axios.create({ timeout: 5000 });
const ok2 = await axios.get(url, { timeout: 3000 });
`)
	findings, _ := CheckTimeouts(dir)
	bySev := findingsBySeverity(findings)
	if bySev[SeverityMedium] != 2 {
		t.Errorf("expected 2 MEDIUM findings, got %v", findings)
	}
}

func TestCheckTimeoutsCommentsAndStringsIgnored(t *testing.T) {
	dir := writeFixture(t, "app.js", `
// const res = await fetch("https://example.com");
/*
const res2 = await fetch("https://example.com");
*/
const doc = "call fetch(url) without options";
const tpl = ` + "`fetch(url)`" + `;
`)
	findings, _ := CheckTimeouts(dir)
	if len(findings) != 0 {
		t.Errorf("expected no findings from comments/strings, got %v", findings)
	}
}

func TestCheckTimeoutsNodeHttp(t *testing.T) {
	// No timeout anywhere: MEDIUM
	dir := writeFixture(t, "server.js", `
const req = https.request({ hostname: "example.com", path: "/" }, (res) => {});
`)
	findings, _ := CheckTimeouts(dir)
	if findingsBySeverity(findings)[SeverityMedium] != 1 {
		t.Errorf("expected 1 MEDIUM finding, got %v", findings)
	}

	// setTimeout used in file: INFO, not MEDIUM
	dir2 := writeFixture(t, "server.js", `
const req = https.get("https://example.com", (res) => {});
req.setTimeout(5000);
`)
	findings2, _ := CheckTimeouts(dir2)
	bySev := findingsBySeverity(findings2)
	if bySev[SeverityInfo] != 1 || bySev[SeverityMedium] != 0 {
		t.Errorf("expected 1 INFO and 0 MEDIUM, got %v", findings2)
	}

	// timeout option set: clean
	dir3 := writeFixture(t, "server.js", `
const req = https.request({ hostname: "example.com", timeout: 5000 });
`)
	findings3, _ := CheckTimeouts(dir3)
	if len(findings3) != 0 {
		t.Errorf("expected no findings, got %v", findings3)
	}
}

func TestCheckTimeoutsSkipsNodeModules(t *testing.T) {
	dir := t.TempDir()
	nm := filepath.Join(dir, "node_modules", "lib")
	if err := os.MkdirAll(nm, 0755); err != nil {
		t.Fatal(err)
	}
	os.WriteFile(filepath.Join(nm, "index.js"), []byte(`fetch("https://example.com")`), 0644)
	os.WriteFile(filepath.Join(dir, "app.js"), []byte(`const x = 1;`), 0644)

	findings, files := CheckTimeouts(dir)
	if files != 1 {
		t.Errorf("files scanned = %d, want 1 (node_modules skipped)", files)
	}
	if len(findings) != 0 {
		t.Errorf("expected no findings, got %v", findings)
	}
}

func TestCheckTimeoutsOnlyScansCodeExtensions(t *testing.T) {
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, "notes.md"), []byte(`fetch("https://example.com")`), 0644)
	os.WriteFile(filepath.Join(dir, "data.json"), []byte(`{"call": "fetch("}`), 0644)
	findings, files := CheckTimeouts(dir)
	if files != 0 || len(findings) != 0 {
		t.Errorf("expected nothing scanned, got %d files %d findings", files, len(findings))
	}
}

func TestSanitizeSource(t *testing.T) {
	src := "const a = 1; // fetch(\"https://x\")\n/* fetch(\"https://y\") */\nconst u = \"https://example.com\";\n"
	clean := sanitizeSource(src)
	// line count preserved
	if len(clean) == 0 {
		t.Fatal("empty output")
	}
	lines := 0
	for _, c := range clean {
		if c == '\n' {
			lines++
		}
	}
	if lines != 3 {
		t.Errorf("line breaks not preserved: got %d newlines, want 3", lines)
	}
	// URL line survives intact: the // in https:// must not start a comment
	// (string contents are blanked by design, so only the quotes remain)
	if !strings.Contains(clean, `const u = "";`) {
		t.Errorf("// inside URL started a comment and ate the line: %q", clean)
	}
	// fetch( inside comments/strings gone
	if strings.Contains(clean, "fetch(") {
		t.Errorf("fetch( leaked through sanitizer: %q", clean)
	}
}
