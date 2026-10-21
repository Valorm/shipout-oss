package scanner

import (
	"fmt"
	"io"
	"net/http"
	"sync/atomic"
	"time"
)

const (
	// requestTimeout is the maximum time to wait for a single HTTP response
	requestTimeout = 15 * time.Second
	// maxRedirects prevents infinite redirect loops
	maxRedirects = 5
	// maxBodySize caps response bodies to prevent memory exhaustion
	maxBodySize = 5 << 20 // 5MB
	// scannerUserAgent identifies Shipout to target servers
	scannerUserAgent = "Shipout/1.0 (security scanner)"
)

// HTTPClient wraps http.Client with request counting and sensible defaults
type HTTPClient struct {
	client   *http.Client
	requests *int64
}

// NewHTTPClient creates a client with timeouts suitable for scanning
func NewHTTPClient(requests *int64) *HTTPClient {
	return &HTTPClient{
		client: &http.Client{
			Timeout: requestTimeout,
			CheckRedirect: func(req *http.Request, via []*http.Request) error {
				if len(via) >= maxRedirects {
					return fmt.Errorf("too many redirects")
				}
				// Every redirect hop is rechecked against the egress policy
				// (docs/trust-boundary.md Zone E: no internal IPs, no
				// metadata APIs), so a public target cannot bounce the
				// scanner into a restricted address.
				return ValidateEgressHost(req.Context(), req.URL.Hostname())
			},
		},
		requests: requests,
	}
}

// Get performs a GET request and returns status, headers, body
func (c *HTTPClient) Get(url string) (int, http.Header, string, error) {
	return c.Do("GET", url, nil)
}

// Do performs an HTTP request with optional headers
func (c *HTTPClient) Do(method, url string, headers map[string]string) (int, http.Header, string, error) {
	atomic.AddInt64(c.requests, 1)

	req, err := http.NewRequest(method, url, nil)
	if err != nil {
		return 0, nil, "", err
	}
	req.Header.Set("User-Agent", scannerUserAgent)

	for k, v := range headers {
		req.Header.Set(k, v)
	}

	resp, err := c.client.Do(req)
	if err != nil {
		return 0, nil, "", err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(resp.Body, maxBodySize))
	if err != nil {
		return resp.StatusCode, resp.Header, "", err
	}

	return resp.StatusCode, resp.Header, string(body), nil
}
