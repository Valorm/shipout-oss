package cmd

import (
	"testing"
)

func TestParsePackageLock(t *testing.T) {
	// npm v7+ format
	data := []byte(`{
		"packages": {
			"": {"version": "1.0.0"},
			"node_modules/express": {"version": "4.18.2"},
			"node_modules/lodash": {"version": "4.17.21"}
		}
	}`)
	pkgs := parsePackageLock(data)
	if len(pkgs) != 2 {
		t.Errorf("expected 2 packages, got %d", len(pkgs))
	}
	if pkgs["express"] != "4.18.2" {
		t.Errorf("express version = %s, want 4.18.2", pkgs["express"])
	}
}

func TestParsePackageLockV6(t *testing.T) {
	// npm v6 format
	data := []byte(`{
		"dependencies": {
			"express": {"version": "4.17.1"},
			"debug": {"version": "2.6.9"}
		}
	}`)
	pkgs := parsePackageLock(data)
	if pkgs["express"] != "4.17.1" {
		t.Errorf("express version = %s, want 4.17.1", pkgs["express"])
	}
}

func TestParsePackageJSON(t *testing.T) {
	data := []byte(`{
		"dependencies": {"express": "^4.18.2"},
		"devDependencies": {"jest": "~29.0.0"}
	}`)
	pkgs := parsePackageJSON(data)
	if pkgs["express"] != "4.18.2" {
		t.Errorf("express version = %s, want 4.18.2 (stripped ^)", pkgs["express"])
	}
	if pkgs["jest"] != "29.0.0" {
		t.Errorf("jest version = %s, want 29.0.0 (stripped ~)", pkgs["jest"])
	}
}

func TestCleanVersion(t *testing.T) {
	tests := []struct{ input, expected string }{
		{"^4.18.2", "4.18.2"},
		{"~29.0.0", "29.0.0"},
		{">=1.0.0", "1.0.0"},
		{"4.18.2", "4.18.2"},
	}
	for _, tt := range tests {
		if got := cleanVersion(tt.input); got != tt.expected {
			t.Errorf("cleanVersion(%s) = %s, want %s", tt.input, got, tt.expected)
		}
	}
}
