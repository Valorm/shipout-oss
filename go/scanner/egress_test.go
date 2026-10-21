package scanner

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestIsRestrictedIP(t *testing.T) {
	restricted := []string{
		"10.1.2.3", "172.16.0.1", "192.168.100.200",
		"127.0.0.1", "169.254.169.254", "169.254.1.1",
		"0.0.0.0", "255.255.255.255",
		"::1", "fc00::1", "fd00::1", "fe80::1",
		"::ffff:10.0.0.1", // IPv4-mapped form must not slip past the IPv4 ranges
	}
	for _, ip := range restricted {
		if !IsRestrictedIP(ip) {
			t.Errorf("IsRestrictedIP(%q) = false, want true", ip)
		}
	}

	allowed := []string{"1.1.1.1", "8.8.8.8", "93.184.216.34", "2606:4700:4700::1111"}
	for _, ip := range allowed {
		if IsRestrictedIP(ip) {
			t.Errorf("IsRestrictedIP(%q) = true, want false", ip)
		}
	}

	if IsRestrictedIP("not-an-ip") {
		t.Errorf("IsRestrictedIP(\"not-an-ip\") = true, want false for unparseable input")
	}
}

func TestIsInternalHostname(t *testing.T) {
	internal := []string{"localhost", "db.internal", "printer.local", "nas.lan", "router.home.arpa"}
	for _, host := range internal {
		if !IsInternalHostname(host) {
			t.Errorf("IsInternalHostname(%q) = false, want true", host)
		}
	}

	if IsInternalHostname("example.com") {
		t.Errorf("IsInternalHostname(\"example.com\") = true, want false")
	}
}

func TestValidateEgressHost(t *testing.T) {
	ctx := context.Background()

	blocked := []string{
		"169.254.169.254", // metadata
		"10.0.0.5",        // private
		"127.0.0.1",       // loopback
		"::1",             // IPv6 loopback
		"localhost",       // internal hostname
		"db.internal",     // internal hostname
	}
	for _, host := range blocked {
		if err := ValidateEgressHost(ctx, host); err == nil {
			t.Errorf("ValidateEgressHost(%q) = nil, want policy error", host)
		}
	}

	// A public IP literal is classified locally, no DNS needed.
	if err := ValidateEgressHost(ctx, "93.184.216.34"); err != nil {
		t.Errorf("ValidateEgressHost(public IP) = %v, want nil", err)
	}
}

func checkRedirect(t *testing.T, client *HTTPClient, target string, via int) error {
	t.Helper()
	req, err := http.NewRequest("GET", target, nil)
	if err != nil {
		t.Fatalf("NewRequest(%q): %v", target, err)
	}
	chain := make([]*http.Request, via)
	for i := range chain {
		chain[i], _ = http.NewRequest("GET", "http://93.184.216.34/", nil)
	}
	return client.client.CheckRedirect(req, chain)
}

func TestCheckRedirectBlocksRestrictedHops(t *testing.T) {
	var count int64
	client := NewHTTPClient(&count)

	targets := []string{
		"http://169.254.169.254/latest/meta-data",
		"http://10.0.0.5/admin",
		"http://127.0.0.1:8080/admin",
		"http://[::1]/admin",
		"http://db.internal/admin",
		"http://localhost/admin",
	}
	for _, target := range targets {
		err := checkRedirect(t, client, target, 1)
		if err == nil {
			t.Errorf("CheckRedirect(%q) = nil, want policy error", target)
			continue
		}
		if !strings.Contains(err.Error(), "policy violation") {
			t.Errorf("CheckRedirect(%q) error = %q, want a policy violation", target, err.Error())
		}
	}
}

func TestCheckRedirectAllowsPublicIPHop(t *testing.T) {
	var count int64
	client := NewHTTPClient(&count)

	if err := checkRedirect(t, client, "http://93.184.216.34/final", 1); err != nil {
		t.Errorf("CheckRedirect(public IP) = %v, want nil", err)
	}
}

func TestCheckRedirectCapStillApplies(t *testing.T) {
	var count int64
	client := NewHTTPClient(&count)

	err := checkRedirect(t, client, "http://93.184.216.34/next", maxRedirects)
	if err == nil || !strings.Contains(err.Error(), "too many redirects") {
		t.Errorf("CheckRedirect(at cap) = %v, want too many redirects", err)
	}
}

func TestRedirectToRestrictedAddressIsNotFollowed(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Location", "http://169.254.169.254/latest/meta-data")
		w.WriteHeader(http.StatusFound)
	}))
	defer server.Close()

	var count int64
	client := NewHTTPClient(&count)
	_, _, _, err := client.Get(server.URL)
	if err == nil {
		t.Fatal("Get with redirect to metadata address = nil error, want policy error")
	}
	if !strings.Contains(err.Error(), "policy violation") {
		t.Errorf("Get error = %q, want it to name the policy violation", err.Error())
	}
}
