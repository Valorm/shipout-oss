package scanner

import "testing"

func TestCalculateScore(t *testing.T) {
	tests := []struct {
		name     string
		findings []Finding
		expected int
	}{
		{"no findings", []Finding{}, 100},
		{"one critical", []Finding{{Severity: SeverityCritical}}, 75},
		{"one high", []Finding{{Severity: SeverityHigh}}, 85},
		{"one medium", []Finding{{Severity: SeverityMedium}}, 90},
		{"mixed", []Finding{
			{Severity: SeverityCritical},
			{Severity: SeverityHigh},
			{Severity: SeverityMedium},
		}, 50},
		{"floor at zero", []Finding{
			{Severity: SeverityCritical},
			{Severity: SeverityCritical},
			{Severity: SeverityCritical},
			{Severity: SeverityCritical},
			{Severity: SeverityCritical},
		}, 0},
	}
	for _, tt := range tests {
		if got := CalculateScore(tt.findings); got != tt.expected {
			t.Errorf("%s: score = %d, want %d", tt.name, got, tt.expected)
		}
	}
}

func TestScoreGrade(t *testing.T) {
	tests := []struct {
		score    int
		expected string
	}{
		{100, "A+"},
		{95, "A+"},
		{94, "A"},
		{90, "A"},
		{89, "B"},
		{80, "B"},
		{79, "C"},
		{70, "C"},
		{69, "D"},
		{60, "D"},
		{59, "F"},
		{0, "F"},
	}
	for _, tt := range tests {
		if got := ScoreGrade(tt.score); got != tt.expected {
			t.Errorf("ScoreGrade(%d) = %s, want %s", tt.score, got, tt.expected)
		}
	}
}
