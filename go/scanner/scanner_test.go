package scanner

import "testing"

func TestIsCatchAll(t *testing.T) {
	tests := []struct {
		name     string
		body     string
		path     string
		expected bool
	}{
		{
			name:     "HTML response for .env path is catch-all",
			body:     `<html><form action="/search"><input name="q"></form></html>`,
			path:     "/.env.local",
			expected: true,
		},
		{
			name:     "Real .env content is not catch-all",
			body:     "SECRET_KEY=abc123\nDB_URL=postgres://x",
			path:     "/.env",
			expected: false,
		},
		{
			name:     "JSON debug response is not catch-all",
			body:     `{"env": {"key": "value"}}`,
			path:     "/debug",
			expected: false,
		},
		{
			name:     "Doctype HTML is catch-all",
			body:     `<!DOCTYPE html><html><body>SPA</body></html>`,
			path:     "/.git/config",
			expected: true,
		},
		{
			name:     "Plain text config is not catch-all",
			body:     "[core]\n\trepositoryformatversion = 0",
			path:     "/.git/config",
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := isCatchAll(tt.body, tt.path); got != tt.expected {
				t.Errorf("isCatchAll() = %v, want %v", got, tt.expected)
			}
		})
	}
}

func TestDecodeJWTClaims(t *testing.T) {
	// JWT with service_role claim (header.payload.signature)
	// payload: {"role":"service_role","exp":123}
	token := "eyJhbGciOiJIUzI1NiJ9.eyJyb2xlIjoic2VydmljZV9yb2xlIiwiZXhwIjoxMjN9.sig"

	claims := decodeJWTClaims(token)
	if claims == nil {
		t.Fatal("decodeJWTClaims returned nil for valid token")
	}
	if claims["role"] != "service_role" {
		t.Errorf("role = %v, want service_role", claims["role"])
	}
}

func TestDecodeJWTClaimsInvalid(t *testing.T) {
	if decodeJWTClaims("not-a-jwt") != nil {
		t.Error("decodeJWTClaims should return nil for invalid token")
	}
	if decodeJWTClaims("a.b") != nil {
		t.Error("decodeJWTClaims should return nil for two-segment token")
	}
}

func TestResolveURL(t *testing.T) {
	tests := []struct {
		base     string
		ref      string
		expected string
	}{
		{"https://example.com", "/search", "https://example.com/search"},
		{"https://example.com/", "/search", "https://example.com/search"},
		{"https://example.com", "https://other.com/x", "https://other.com/x"},
	}

	for _, tt := range tests {
		if got := resolveURL(tt.base, tt.ref); got != tt.expected {
			t.Errorf("resolveURL(%q, %q) = %q, want %q", tt.base, tt.ref, got, tt.expected)
		}
	}
}

func TestDiscoverProbeTargets(t *testing.T) {
	body := `<html><form action="/search"><input name="q"></form><form action='/find'><input name='s'></form></html>`
	targets := discoverProbeTargets("https://example.com", body)

	found := map[string]bool{}
	for _, tg := range targets {
		found[tg] = true
	}

	if !found["https://example.com/search"] {
		t.Error("should discover /search from form action")
	}
	if !found["https://example.com/find"] {
		t.Error("should discover /find from form action")
	}
}
