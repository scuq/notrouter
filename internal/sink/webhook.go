package sink

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"text/template"
	"time"

	"github.com/scuq/notrouter/internal/source"
)

type Webhook struct {
	url         string
	authToken   string
	hmacSecret  string
	hmacHeader  string
	contentType string
	tmpl        *template.Template
	maxRetries  int
	client      *http.Client
	sleep       func(time.Duration)
}

type WebhookOption func(*Webhook) error

func WithMaxRetries(n int) WebhookOption {
	return func(w *Webhook) error { w.maxRetries = n; return nil }
}

func WithAuthToken(token string) WebhookOption {
	return func(w *Webhook) error { w.authToken = token; return nil }
}

func WithHMAC(secret, header string) WebhookOption {
	return func(w *Webhook) error {
		w.hmacSecret = secret
		if header == "" {
			header = "X-Signature"
		}
		w.hmacHeader = header
		return nil
	}
}

func WithTemplate(tmpl string) WebhookOption {
	return func(w *Webhook) error {
		if tmpl == "" {
			return nil
		}
		t, err := template.New("webhook").Parse(tmpl)
		if err != nil {
			return fmt.Errorf("parse template: %w", err)
		}
		w.tmpl = t
		return nil
	}
}

func WithContentType(ct string) WebhookOption {
	return func(w *Webhook) error { w.contentType = ct; return nil }
}

func NewWebhook(url string, opts ...WebhookOption) (*Webhook, error) {
	w := &Webhook{
		url:         url,
		contentType: "application/json",
		client:      &http.Client{Timeout: 10 * time.Second},
		sleep:       time.Sleep,
	}
	for _, opt := range opts {
		if err := opt(w); err != nil {
			return nil, err
		}
	}
	return w, nil
}

func (s *Webhook) Deliver(ev source.Event) error {
	body, err := s.renderBody(ev)
	if err != nil {
		return err
	}

	var lastErr error
	for attempt := 0; attempt <= s.maxRetries; attempt++ {
		if attempt > 0 {
			s.sleep(backoff(attempt))
		}
		err := s.post(body)
		if err == nil {
			return nil
		}
		lastErr = err
	}
	return lastErr
}

func (s *Webhook) renderBody(ev source.Event) ([]byte, error) {
	if s.tmpl == nil {
		return json.Marshal(ev)
	}
	var buf bytes.Buffer
	if err := s.tmpl.Execute(&buf, ev); err != nil {
		return nil, fmt.Errorf("render template: %w", err)
	}
	return buf.Bytes(), nil
}

func (s *Webhook) post(body []byte) error {
	req, err := http.NewRequest(http.MethodPost, s.url, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", s.contentType)
	if s.authToken != "" {
		req.Header.Set("Authorization", "Bearer "+s.authToken)
	}
	if s.hmacSecret != "" {
		mac := hmac.New(sha256.New, []byte(s.hmacSecret))
		mac.Write(body)
		req.Header.Set(s.hmacHeader, "sha256="+hex.EncodeToString(mac.Sum(nil)))
	}
	resp, err := s.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		b, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		return fmt.Errorf("webhook %s: status %d: %s", s.url, resp.StatusCode, b)
	}
	return nil
}

func backoff(attempt int) time.Duration {
	d := 100 * time.Millisecond
	for i := 1; i < attempt; i++ {
		d *= 2
	}
	if d > 5*time.Second {
		d = 5 * time.Second
	}
	return d
}
