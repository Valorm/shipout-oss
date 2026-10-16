package scanner

import (
	"sync"
	"time"
)

// Run executes all checks against the target concurrently
func Run(target string) *ScanResult {
	start := time.Now()
	var requestCount int64

	ctx := &ScanContext{
		Target: target,
		Client: NewHTTPClient(&requestCount),
	}

	checks := []Check{
		CheckTargetAlive,
		CheckSecurityHeaders,
		CheckSensitiveFiles,
		CheckCORS,
		CheckCookies,
		CheckSupabase,
		CheckStackTraces,
		CheckXSS,
		CheckHardcodedSecrets,
		CheckPIILeakage,
	}

	var wg sync.WaitGroup
	findingsCh := make(chan []Finding, len(checks))

	for _, check := range checks {
		wg.Add(1)
		go func(c Check) {
			defer wg.Done()
			// Recover from panics in individual checks so one bad check
			// doesn't kill the whole scan
			defer func() {
				if r := recover(); r != nil {
					findingsCh <- nil
				}
			}()
			findingsCh <- c(ctx)
		}(check)
	}

	wg.Wait()
	close(findingsCh)

	var findings []Finding
	for f := range findingsCh {
		findings = append(findings, f...)
	}

	return &ScanResult{
		Target:       target,
		DurationMs:   time.Since(start).Milliseconds(),
		RequestCount: int(requestCount),
		Findings:     findings,
	}
}
