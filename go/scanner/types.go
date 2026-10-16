package scanner

// Severity levels for findings
type Severity string

const (
	SeverityInfo     Severity = "INFO"
	SeverityLow      Severity = "LOW"
	SeverityMedium   Severity = "MEDIUM"
	SeverityHigh     Severity = "HIGH"
	SeverityCritical Severity = "CRITICAL"
)

// Finding is a single security issue discovered by a check
type Finding struct {
	Type        string   `json:"type"`
	Description string   `json:"description"`
	Severity    Severity `json:"severity"`
	Endpoint    string   `json:"endpoint,omitempty"`
	Evidence    []string `json:"evidence,omitempty"`
	Remediation string   `json:"remediation,omitempty"`
	Agent       string   `json:"agent,omitempty"`
}

// ScanResult holds the complete results of a scan
type ScanResult struct {
	Target         string    `json:"target"`
	DurationMs     int64     `json:"duration_ms"`
	RequestCount   int       `json:"request_count"`
	Findings       []Finding `json:"findings"`
}

// Check is a single security check that runs against a target
type Check func(ctx *ScanContext) []Finding

// ScanContext carries shared state between checks
type ScanContext struct {
	Target   string
	Client   *HTTPClient
	Findings []Finding
}
