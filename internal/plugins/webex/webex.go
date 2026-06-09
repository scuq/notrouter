package webex

import (
	"context"
	"log/slog"
	"encoding/json"
	"fmt"
	"text/template"
	"unicode/utf8"
	"time"

	"github.com/scuq/notrouter/internal/event"
	"github.com/scuq/notrouter/internal/plugins"
	"github.com/scuq/notrouter/internal/plugins/httpsink"
)

// defaultTemplate is the markdown body sent to Webex when the user doesn't
// override it. The emoji prefix mirrors the eyecatcher pattern from the
// Nagios Python notify_webhook.py script (✅ ⚠️ ❌ ❓) so behavior is
// recognizable to anyone migrating from that script.
const defaultTemplate = `{{- if eq .Urgency "critical" -}}❌
{{- else if eq .Urgency "high" -}}❌
{{- else if eq .Urgency "medium" -}}⚠️
{{- else if eq .Urgency "low" -}}ℹ️
{{- else if eq .Urgency "info" -}}✅
{{- else -}}❓
{{- end }} **{{.Topic}}** on ` + "`{{.Entity}}`" + `

{{- if .Attributes.msg }}

{{.Attributes.msg}}
{{- end }}

{{- if .Attributes.app }}

_app: {{.Attributes.app}}_
{{- end }}`

type plugin struct{}

func (p *plugin) Type() string { return "webex" }

func (p *plugin) New(name string, cfg map[string]interface{}) (plugins.Instance, error) {
	urlS, ok := cfg["webhook_url"].(string)
	if !ok || urlS == "" {
		return nil, fmt.Errorf("webex %q: webhook_url required", name)
	}

	tplBody := defaultTemplate
	if t, ok := cfg["template"].(string); ok && t != "" {
		tplBody = t
	}
	tpl, err := plugins.CompileTemplate("webex:"+name, tplBody)
	if err != nil {
		return nil, fmt.Errorf("webex %q: template: %w", name, err)
	}

	timeout := 10 * time.Second
	if s, ok := cfg["timeout"].(string); ok {
		if d, err := time.ParseDuration(s); err == nil {
			timeout = d
		}
	}
	grace := 2 * time.Second
	if s, ok := cfg["rate_limit_grace"].(string); ok {
		if d, err := time.ParseDuration(s); err == nil {
			grace = d
		}
	}
	proxy, _ := cfg["proxy"].(string)
	insecure, _ := cfg["insecure_skip_verify"].(bool)

	// Webex's incoming webhook API rejects messages >7439 characters
	// with non-retryable HTTP 400. Default to 7000 for headroom; let
	// operators tune per-instance. Zero disables truncation entirely
	// (caller takes the risk).
	maxChars := 7000
	if v, ok := cfg["max_message_chars"].(int); ok {
		maxChars = v
	} else if v, ok := cfg["max_message_chars"].(float64); ok {
		// YAML numerics decode as float64 in untyped maps.
		maxChars = int(v)
	}
	truncateSuffix := "\n\n*... [truncated]*"
	if s, ok := cfg["truncate_suffix"].(string); ok {
		truncateSuffix = s
	}

	// Headers exactly match the Python reference: matches what the Webex
	// incoming-webhook endpoint expects and what the production-tested
	// Nagios script has been sending for years.
	headers := map[string]string{
		"Accept":        "application/json; charset=utf-8",
		"Content-Type":  "application/json",
		"Cache-Control": "no-cache",
	}

	client, err := httpsink.New(httpsink.Config{
		URL:                urlS,
		Method:             "POST",
		Headers:            headers,
		Timeout:            timeout,
		Proxy:              proxy,
		InsecureSkipVerify: insecure,
		RateLimitGrace:     grace,
	})
	if err != nil {
		return nil, fmt.Errorf("webex %q: %w", name, err)
	}

	return &instance{
		name:            name,
		client:          client,
		tpl:             tpl,
		maxMessageChars: maxChars,
		truncateSuffix:  truncateSuffix,
	}, nil
}

type instance struct {
	name            string
	client          *httpsink.Client
	tpl             *template.Template
	maxMessageChars int    // hard cap on rendered template length, 0 = unlimited
	truncateSuffix  string // appended when truncation happens; included in the cap
}

func (i *instance) Name() string { return i.name }

func (i *instance) Send(ctx context.Context, ev *event.Event) error {
	markdown, err := plugins.RenderEvent(i.tpl, ev)
	if err != nil {
		// Template errors are non-retryable - the template won't change
		// between attempts, so failing fast saves the retry budget for
		// transient network/server issues.
		return &httpsink.NonRetryableError{StatusCode: 0, Body: "template: " + err.Error()}
	}

	// Truncate if the rendered output exceeds the per-instance cap.
	// utf8.RuneCountInString counts characters, not bytes - Webex's
	// limit is character-based, and our German/emoji content is
	// multi-byte. Truncation preserves rune boundaries (no broken UTF-8).
	if i.maxMessageChars > 0 {
		if n := utf8.RuneCountInString(markdown); n > i.maxMessageChars {
			markdown = truncateToRunes(markdown, i.maxMessageChars-utf8.RuneCountInString(i.truncateSuffix)) + i.truncateSuffix
			slog.Info("webex message truncated",
				"instance", i.name,
				"event", ev.ID,
				"original_chars", n,
				"max_chars", i.maxMessageChars,
				"dropped_chars", n-i.maxMessageChars+utf8.RuneCountInString(i.truncateSuffix))
		}
	}

	// Webex expects {"markdown": "..."} - same envelope the Python script
	// builds. We let json.Marshal handle escaping rather than concatenating,
	// otherwise newlines and quotes in the rendered template break the
	// JSON body.
	body, err := json.Marshal(map[string]string{"markdown": markdown})
	if err != nil {
		return err
	}
	return i.client.Send(ctx, body, nil)
}

// truncateToRunes returns s truncated to at most n runes. Unlike
// slicing strings by byte index, this never splits a multi-byte rune
// in half.
func truncateToRunes(s string, n int) string {
	if n <= 0 {
		return ""
	}
	if utf8.RuneCountInString(s) <= n {
		return s
	}
	count := 0
	for i := range s {
		if count == n {
			return s[:i]
		}
		count++
	}
	return s
}

func (i *instance) Close() error { return nil }

func init() { plugins.Register(&plugin{}) }
