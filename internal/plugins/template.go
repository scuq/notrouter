package plugins

import (
	"bytes"
	"strings"
	"text/template"

	"github.com/scuq/notrouter/internal/event"
)

// templateFuncs mirrors the normalizer set so user templates feel uniform
// across config files. If you change one, change the other.
var templateFuncs = template.FuncMap{
	"lower":     strings.ToLower,
	"upper":     strings.ToUpper,
	"trim":      strings.TrimSpace,
	"trimspace": strings.TrimSpace,
	"replace":   func(old, new, s string) string { return strings.ReplaceAll(s, old, new) },
	"contains":  strings.Contains,
	"hasprefix": strings.HasPrefix,
	"hassuffix": strings.HasSuffix,
	"split":     strings.Split,
	"join":      strings.Join,
	"default": func(def string, s string) string {
		if s == "" {
			return def
		}
		return s
	},
	"coalesce": func(vals ...string) string {
		for _, v := range vals {
			if v != "" {
				return v
			}
		}
		return ""
	},
	"match": func(pattern, s string) bool { return strings.Contains(s, pattern) },
}

// CompileTemplate parses a template string with the standard helper set.
// Empty string returns nil (caller should treat that as "use default").
func CompileTemplate(name, body string) (*template.Template, error) {
	if body == "" {
		return nil, nil
	}
	return template.New(name).Funcs(templateFuncs).Parse(body)
}

// RenderEvent runs the template against an event. The context shape is the
// same one the normalizer uses, plus Urgency as a top-level field for
// convenience (so user templates can write `{{.Urgency}}` instead of
// fishing it out of attributes).
func RenderEvent(t *template.Template, ev *event.Event) (string, error) {
	if t == nil {
		return "", nil
	}
	var buf bytes.Buffer
	ctx := map[string]interface{}{
		"ID":         ev.ID,
		"Source":     ev.Source,
		"Entity":     ev.Entity,
		"Topic":      ev.Topic,
		"Urgency":    string(ev.Urgency),
		"Timestamp":  ev.Timestamp,
		"Attributes": ev.Attributes,
	}
	if err := t.Execute(&buf, ctx); err != nil {
		return "", err
	}
	return buf.String(), nil
}
