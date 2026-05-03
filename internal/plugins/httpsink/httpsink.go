// Package httpsink provides a shared HTTP sender for plugins that POST to
// webhook-style endpoints (generic webhooks, Webex, Slack, Discord, etc.).
// It handles:
//
//   - Per-instance *http.Client with timeout, optional proxy, optional
//     SSL-verify-skip, and connection pooling
//   - Redirect policy: do not follow (matches the Python reference impl)
//   - Status classification:
//       2xx        -> success
//       429        -> RetryableError with parsed Retry-After
//       5xx        -> RetryableError without delay
//       other 4xx  -> NonRetryableError (auth wrong, body bad, etc.)
//
// The retry loop in dispatch consumes RetryableError.Delay to respect
// server-supplied backoff hints (the "Retry-After" header behavior carried
// over from the Nagios Python script).
package httpsink

import (
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"time"
)

// Config is set up once per plugin instance at startup.
type Config struct {
	URL                string
	Method             string            // default "POST"
	Headers            map[string]string // additional headers
	Body               []byte            // pre-rendered body
	Timeout            time.Duration     // default 10s
	Proxy              string            // optional, e.g. "http://proxy:8080"
	InsecureSkipVerify bool              // optional, defaults secure
	RateLimitGrace     time.Duration     // added to Retry-After value, default 2s
}

// Client is a long-lived sender bound to a single Config. Reuses the
// underlying *http.Client for connection pooling.
type Client struct {
	cfg  Config
	http *http.Client
}

// RetryableError signals that the dispatch retry loop should try again.
// Delay is a hint (from Retry-After when set, zero otherwise); the dispatch
// loop combines it with its own backoff schedule.
type RetryableError struct {
	StatusCode int
	Delay      time.Duration
	Body       string
}

func (e *RetryableError) Error() string {
	return fmt.Sprintf("retryable HTTP %d (delay=%s): %s", e.StatusCode, e.Delay, truncate(e.Body, 200))
}

// NonRetryableError signals a permanent failure. The dispatch loop should
// give up immediately and record the failure rather than burn retries.
type NonRetryableError struct {
	StatusCode int
	Body       string
}

func (e *NonRetryableError) Error() string {
	return fmt.Sprintf("non-retryable HTTP %d: %s", e.StatusCode, truncate(e.Body, 200))
}

// IsRetryable lets the dispatch retry loop inspect an error without
// type-asserting. Network errors (DNS, connection refused, TLS) are also
// retryable - they're returned as plain errors and we treat unknown errors
// as retryable too, since "give up after N attempts" handles it correctly.
func IsRetryable(err error) (delay time.Duration, retryable bool) {
	if err == nil {
		return 0, false
	}
	var re *RetryableError
	if errors.As(err, &re) {
		return re.Delay, true
	}
	var nre *NonRetryableError
	if errors.As(err, &nre) {
		return 0, false
	}
	// Plain errors (network-level): retry.
	return 0, true
}

// New builds a Client. Returns an error if proxy URL is malformed.
func New(cfg Config) (*Client, error) {
	if cfg.Method == "" {
		cfg.Method = "POST"
	}
	if cfg.Timeout == 0 {
		cfg.Timeout = 10 * time.Second
	}
	if cfg.RateLimitGrace == 0 {
		cfg.RateLimitGrace = 2 * time.Second
	}

	tr := &http.Transport{
		// Reasonable connection pool defaults for plugins that send to a
		// single endpoint at modest QPS. Tune later if a plugin needs more.
		MaxIdleConns:        4,
		MaxIdleConnsPerHost: 4,
		IdleConnTimeout:     90 * time.Second,
		TLSClientConfig:     &tls.Config{InsecureSkipVerify: cfg.InsecureSkipVerify},
	}

	if cfg.Proxy != "" {
		pu, err := url.Parse(cfg.Proxy)
		if err != nil {
			return nil, fmt.Errorf("proxy url: %w", err)
		}
		tr.Proxy = http.ProxyURL(pu)
	}

	c := &http.Client{
		Transport: tr,
		Timeout:   cfg.Timeout,
		// Match Python reference: do not follow redirects. Webhook providers
		// returning a redirect almost always indicate a configuration error
		// (wrong room URL, deprecated endpoint) - silently following them
		// hides bugs and risks leaking auth headers across hosts.
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	return &Client{cfg: cfg, http: c}, nil
}

// Send executes one HTTP attempt. Caller (the dispatch retry loop) handles
// retries. Body and headers come from cfg, which means a single plugin
// instance sends the same shape every time - templates render the body
// upstream, before this is called.
func (c *Client) Send(ctx context.Context, body []byte, extraHeaders map[string]string) error {
	req, err := http.NewRequestWithContext(ctx, c.cfg.Method, c.cfg.URL, bytes.NewReader(body))
	if err != nil {
		return err
	}
	for k, v := range c.cfg.Headers {
		req.Header.Set(k, v)
	}
	for k, v := range extraHeaders {
		req.Header.Set(k, v)
	}

	resp, err := c.http.Do(req)
	if err != nil {
		return err // network-level; retryable per IsRetryable
	}
	defer resp.Body.Close()

	respBody, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))

	switch {
	case resp.StatusCode >= 200 && resp.StatusCode < 300:
		return nil
	case resp.StatusCode == http.StatusTooManyRequests:
		return &RetryableError{
			StatusCode: resp.StatusCode,
			Delay:      c.parseRetryAfter(resp.Header.Get("Retry-After")),
			Body:       string(respBody),
		}
	case resp.StatusCode >= 500:
		return &RetryableError{
			StatusCode: resp.StatusCode,
			Body:       string(respBody),
		}
	default:
		return &NonRetryableError{
			StatusCode: resp.StatusCode,
			Body:       string(respBody),
		}
	}
}

// parseRetryAfter handles both formats the spec allows:
//
//	Retry-After: 120              <- seconds
//	Retry-After: Wed, 21 Oct ...  <- HTTP-date
//
// On success returns the delay plus the configured grace. On parse failure
// returns 0 (retry loop falls back to its own backoff).
func (c *Client) parseRetryAfter(h string) time.Duration {
	if h == "" {
		return 0
	}
	if secs, err := strconv.Atoi(h); err == nil && secs >= 0 {
		return time.Duration(secs)*time.Second + c.cfg.RateLimitGrace
	}
	if t, err := http.ParseTime(h); err == nil {
		d := time.Until(t)
		if d < 0 {
			d = 0
		}
		return d + c.cfg.RateLimitGrace
	}
	return 0
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "..."
}
