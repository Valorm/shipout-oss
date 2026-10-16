package scanner

import (
	"fmt"
	"io"
	"net/http"
	"sync/atomic"
	"time"
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
			Timeout: 15 * time.Second,
			CheckRedirect: func(req *http.Request, via []*http.Request) error {
				if len(via) >= 5 {
					return fmt.Errorf("too many redirects")
				}
				return nil
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
	req.Header.Set("User-Agent", "Shipout/1.0 (security scanner)")

	for k, v := range headers {
		req.Header.Set(k, v)
	}

	resp, err := c.client.Do(req)
	if err != nil {
		return 0, nil, "", err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(resp.Body, 5<<20)) // 5MB cap
	if err != nil {
		return resp.StatusCode, resp.Header, "", err
	}

	return resp.StatusCode, resp.Header, string(body), nil
}
