package scanner

// Severity weights for score calculation
var severityWeights = map[Severity]int{
	SeverityCritical: 25,
	SeverityHigh:     15,
	SeverityMedium:   10,
	SeverityLow:      5,
	SeverityInfo:     1,
}

// CalculateScore computes a 0-100 security score from findings.
// Starts at 100, deducts weighted points per finding.
func CalculateScore(findings []Finding) int {
	score := 100
	for _, f := range findings {
		if w, ok := severityWeights[f.Severity]; ok {
			score -= w
		}
	}
	if score < 0 {
		score = 0
	}
	return score
}

// ScoreGrade maps a numeric score to a letter grade.
func ScoreGrade(score int) string {
	switch {
	case score >= 95:
		return "A+"
	case score >= 90:
		return "A"
	case score >= 80:
		return "B"
	case score >= 70:
		return "C"
	case score >= 60:
		return "D"
	default:
		return "F"
	}
}
