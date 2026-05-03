package webhook

import (
	"context"
	"encoding/json"
	"fmt"
	"text/template"
	"time"

	"github.com/scuq/notrouter/internal/event"
	"github.com/scuq/notrouter/internal/plugins"
	"github.com/scuq/notrouter/internal/plugins/httpsink"
)

type plugin struct{}

func (p *plugin) Type() string { return "webhook" }

func (p *plugin) New(name string, cfg map[string]interface{}) (plugins.Instance, error) {
	urlS, err := requireString(cfg, "webhook_url", name)
	if err != nil {
		return nil, err
	}

	method := stringOr(cfg, "method", "POST")
	contentType := stringOr(cfg, "content_type", "application/json")
	tplBody := stringOr(cfg, "template", "")

	headers := map[string]string{
		"Content-Type": contentType,
	}
	for k, v := range mapOr(cfg, "headers") {
		if s, ok := v.(string); ok {
			headers[k] = s
		}
	}

	tpl, err := plugins.CompileTemplate("webhook:"+name, tplBody)
	if err != nil {
		return nil, fmt.Errorf("webhook %q: template: %w", name, err)
	}

	hsCfg := httpsink.Config{
		URL:                urlS,
		Method:             method,
		Headers:            headers,
		Timeout:            durationOr(cfg, "timeout", 10*time.Second),
		Proxy:              stringOr(cfg, "proxy", ""),
		InsecureSkipVerify: boolOr(cfg, "insecure_skip_verify", false),
		RateLimitGrace:     durationOr(cfg, "rate_limit_grace", 2*time.Second),
	}

	client, err := httpsink.New(hsCfg)
	if err != nil {
		return nil, fmt.Errorf("webhook %q: %w", name, err)
	}

	return &instance{
		name:        name,
		client:      client,
		tpl:         tpl,
		fallbackJSON: tpl == nil,
	}, nil
}

type instance struct {
	name         string
	client       *httpsink.Client
	tpl          *template.Template
	fallbackJSON bool
}

func (i *instance) Name() string { return i.name }

func (i *instance) Send(ctx context.Context, ev *event.Event) error {
	body, err := i.renderBody(ev)
	if err != nil {
		// Template errors are non-retryable.
		return &httpsink.NonRetryableError{StatusCode: 0, Body: "render: " + err.Error()}
	}
	return i.client.Send(ctx, body, nil)
}

func (i *instance) Close() error { return nil }

func (i *instance) renderBody(ev *event.Event) ([]byte, error) {
	if i.fallbackJSON {
		// No template configured - send the canonical event as JSON. Same
		// shape the file plugin writes.
		return json.Marshal(map[string]interface{}{
			"id":         ev.ID,
			"source":     ev.Source,
			"entity":     ev.Entity,
			"topic":      ev.Topic,
			"urgency":    ev.Urgency,
			"timestamp":  ev.Timestamp,
			"attributes": ev.Attributes,
		})
	}
	out, err := plugins.RenderEvent(i.tpl, ev)
	if err != nil {
		return nil, err
	}
	return []byte(out), nil
}

// --- tiny config-map helpers (kept here so each plugin file is self-
// contained; they're a few lines and don't justify their own package) ---

func requireString(cfg map[string]interface{}, key, name string) (string, error) {
	v, ok := cfg[key]
	if !ok {
		return "", fmt.Errorf("webhook %q: missing %q", name, key)
	}
	s, ok := v.(string)
	if !ok {
		return "", fmt.Errorf("webhook %q: %q must be string", name, key)
	}
	return s, nil
}

func stringOr(cfg map[string]interface{}, key, def string) string {
	if v, ok := cfg[key]; ok {
		if s, ok := v.(string); ok {
			return s
		}
	}
	return def
}

func boolOr(cfg map[string]interface{}, key string, def bool) bool {
	if v, ok := cfg[key]; ok {
		if b, ok := v.(bool); ok {
			return b
		}
	}
	return def
}

func durationOr(cfg map[string]interface{}, key string, def time.Duration) time.Duration {
	if v, ok := cfg[key]; ok {
		if s, ok := v.(string); ok {
			if d, err := time.ParseDuration(s); err == nil {
				return d
			}
		}
	}
	return def
}

func mapOr(cfg map[string]interface{}, key string) map[string]interface{} {
	if v, ok := cfg[key]; ok {
		if m, ok := v.(map[string]interface{}); ok {
			return m
		}
	}
	return nil
}

func init() { plugins.Register(&plugin{}) }
