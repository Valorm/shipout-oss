package scanner

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestCheckPIILeakage(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/api/users", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`[{"name":"John","email":"john@realcompany.com","phone":"+233201234567"}]`))
	})
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`<html></html>`))
	})
	server := httptest.NewServer(mux)
	defer server.Close()

	var count int64
	ctx := &ScanContext{Target: server.URL, Client: NewHTTPClient(&count)}
	findings := CheckPIILeakage(ctx)

	if len(findings) == 0 {
		t.Fatal("expected PII finding, got none")
	}
	found := false
	for _, f := range findings {
		if f.Type == "pii_leakage" && f.Severity == SeverityHigh {
			found = true
		}
	}
	if !found {
		t.Error("expected pii_leakage HIGH finding")
	}
}

func TestCheckPIILeakageClean(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/api/users", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`[{"id":1,"name":"John"}]`))
	})
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`<html></html>`))
	})
	server := httptest.NewServer(mux)
	defer server.Close()

	var count int64
	ctx := &ScanContext{Target: server.URL, Client: NewHTTPClient(&count)}
	findings := CheckPIILeakage(ctx)
	if len(findings) != 0 {
		t.Errorf("expected no findings for clean API, got %d", len(findings))
	}
}

func TestCheckPIILeakageFiltersExample(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/api/users", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`[{"email":"test@example.com"}]`))
	})
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`<html></html>`))
	})
	server := httptest.NewServer(mux)
	defer server.Close()

	var count int64
	ctx := &ScanContext{Target: server.URL, Client: NewHTTPClient(&count)}
	findings := CheckPIILeakage(ctx)
	if len(findings) != 0 {
		t.Errorf("example.com emails should be filtered, got %d findings", len(findings))
	}
}
