package webex

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

	return &instance{name: name, client: client, tpl: tpl}, nil
}

type instance struct {
	name   string
	client *httpsink.Client
	tpl    *template.Template
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

func (i *instance) Close() error { return nil }

func init() { plugins.Register(&plugin{}) }
