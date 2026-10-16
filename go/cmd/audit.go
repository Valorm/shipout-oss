package cmd

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// OSV API for vulnerability lookup (free, no API key required)
const osvURL = "https://api.osv.dev/v1/query"

type osvQuery struct {
	Package osvPackage `json:"package"`
	Version string      `json:"version"`
}

type osvPackage struct {
	Name      string `json:"name"`
	Ecosystem string `json:"ecosystem"`
}

type osvResponse struct {
	Vulns []osvVuln `json:"vulns"`
}

type osvVuln struct {
	ID      string `json:"id"`
	Summary string `json:"summary"`
	Details string `json:"details"`
	Severity []osvSeverity `json:"severity"`
}

type osvSeverity struct {
	Type  string `json:"type"`
	Score string `json:"score"`
}

type packageLock struct {
	Packages map[string]packageInfo `json:"packages"`
	Dependencies map[string]packageInfo `json:"dependencies"`
}

type packageInfo struct {
	Version string `json:"version"`
}

// RunAudit scans local dependencies for known vulnerabilities
func RunAudit(path string) {
	lockPath := filepath.Join(path, "package-lock.json")
	data, err := os.ReadFile(lockPath)
	if err != nil {
		// Try package.json as fallback
		lockPath = filepath.Join(path, "package.json")
		data, err = os.ReadFile(lockPath)
		if err != nil {
			fmt.Printf("No package-lock.json or package.json found in %s\n", path)
			os.Exit(1)
		}
		fmt.Printf("Using package.json (install dependencies for more accurate results)\n\n")
	}

	var packages map[string]string // name -> version
	if strings.HasSuffix(lockPath, "package-lock.json") {
		packages = parsePackageLock(data)
	} else {
		packages = parsePackageJSON(data)
	}

	if len(packages) == 0 {
		fmt.Println("No dependencies found.")
		return
	}

	fmt.Printf("  Shipout Dependency Audit\n  Scanning %d packages...\n\n", len(packages))

	client := &http.Client{Timeout: 10 * time.Second}
	vulnCount := 0

	for name, version := range packages {
		vulns := queryOSV(client, name, version)
		for _, v := range vulns {
			vulnCount++
			severity := "UNKNOWN"
			if len(v.Severity) > 0 {
				severity = v.Severity[0].Score
			}
			fmt.Printf("  [%s] %s@%s\n", severity, name, version)
			fmt.Printf("  %s: %s\n", v.ID, v.Summary)
			if v.Details != "" && len(v.Details) < 200 {
				fmt.Printf("  %s\n", v.Details)
			}
			fmt.Println()
		}
	}

	if vulnCount == 0 {
		fmt.Println("  No known vulnerabilities found.")
	} else {
		fmt.Printf("  Found %d vulnerabilities.\n", vulnCount)
		os.Exit(1)
	}
}

func parsePackageLock(data []byte) map[string]string {
	var lock packageLock
	if err := json.Unmarshal(data, &lock); err != nil {
		return map[string]string{}
	}
	result := map[string]string{}
	// npm v7+ format
	for path, info := range lock.Packages {
		if path == "" || info.Version == "" {
			continue
		}
		// path is like "node_modules/express"
		name := strings.TrimPrefix(path, "node_modules/")
		if !strings.Contains(name, "node_modules/") {
			result[name] = info.Version
		}
	}
	// npm v6 format fallback
	for name, info := range lock.Dependencies {
		if info.Version != "" {
			result[name] = info.Version
		}
	}
	return result
}

func parsePackageJSON(data []byte) map[string]string {
	var pkg struct {
		Dependencies    map[string]string `json:"dependencies"`
		DevDependencies map[string]string `json:"devDependencies"`
	}
	if err := json.Unmarshal(data, &pkg); err != nil {
		return map[string]string{}
	}
	result := map[string]string{}
	for name, version := range pkg.Dependencies {
		result[name] = cleanVersion(version)
	}
	for name, version := range pkg.DevDependencies {
		result[name] = cleanVersion(version)
	}
	return result
}

func cleanVersion(v string) string {
	// Strip ^, ~, >=, etc.
	v = strings.TrimLeft(v, "^~>=< ")
	// Take first part before space or ||
	parts := strings.Fields(v)
	if len(parts) > 0 {
		return parts[0]
	}
	return v
}

func queryOSV(client *http.Client, name, version string) []osvVuln {
	query := osvQuery{
		Package: osvPackage{Name: name, Ecosystem: "npm"},
		Version: version,
	}
	body, _ := json.Marshal(query)
	resp, err := client.Post(osvURL, "application/json", strings.NewReader(string(body)))
	if err != nil {
		return nil
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return nil
	}

	var result osvResponse
	if err := json.Unmarshal(respBody, &result); err != nil {
		return nil
	}
	return result.Vulns
}
