package parser

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"strings"
	"sync"
	"text/template"

	"github.com/scuq/notrouter/internal/config"
	"github.com/scuq/notrouter/internal/event"
	"github.com/scuq/notrouter/internal/jsonpath"
	"github.com/scuq/notrouter/internal/pipeline"
)

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

type compiledNormalize struct {
	topicTpl    *template.Template
	urgencyJSON string
	urgencyMap  map[string]event.Urgency
	attributes  map[string]config.AttributeExtractor
}

type Normalizer struct {
	in       <-chan *pipeline.RawEvent
	out      chan<- *event.Event
	profiles map[string]*compiledNormalize
	workers  int
	log      *slog.Logger
}

func NewNormalizer(
	in <-chan *pipeline.RawEvent,
	out chan<- *event.Event,
	profileCfgs map[string]config.ProfileConfig,
	workers int,
	log *slog.Logger,
) (*Normalizer, error) {
	profiles := make(map[string]*compiledNormalize, len(profileCfgs))
	for name, pc := range profileCfgs {
		cn := &compiledNormalize{
			urgencyJSON: pc.Normalize.Urgency.FromJSON,
			urgencyMap:  make(map[string]event.Urgency, len(pc.Normalize.Urgency.Map)),
			attributes:  pc.Attributes,
		}
		if pc.Normalize.Topic != "" {
			tpl, err := template.New("topic:" + name).Funcs(templateFuncs).Parse(pc.Normalize.Topic)
			if err != nil {
				return nil, fmt.Errorf("profile %q topic template: %w", name, err)
			}
			cn.topicTpl = tpl
		}
		for raw, mapped := range pc.Normalize.Urgency.Map {
			cn.urgencyMap[strings.ToUpper(raw)] = event.Urgency(mapped)
		}
		profiles[name] = cn

		// Diagnostic line - if attributes:{} in YAML didn't parse, this
		// will say 0 and we'll know immediately rather than chasing a
		// silent miss in production.
		log.Info("normalizer profile loaded",
			"profile", name,
			"has_topic_template", cn.topicTpl != nil,
			"urgency_map_entries", len(cn.urgencyMap),
			"attribute_extractors", len(cn.attributes))
	}
	return &Normalizer{
		in:       in,
		out:      out,
		profiles: profiles,
		workers:  workers,
		log:      log,
	}, nil
}

func (n *Normalizer) Name() string { return "normalizer" }

func (n *Normalizer) Run(ctx context.Context, wg *sync.WaitGroup) {
	defer wg.Done()
	var workerWg sync.WaitGroup
	for i := 0; i < n.workers; i++ {
		workerWg.Add(1)
		go n.worker(ctx, &workerWg)
	}
	workerWg.Wait()
	close(n.out)
}

func (n *Normalizer) worker(ctx context.Context, wg *sync.WaitGroup) {
	defer wg.Done()
	for {
		select {
		case <-ctx.Done():
			return
		case raw, ok := <-n.in:
			if !ok {
				return
			}
			n.normalize(raw)
			select {
			case n.out <- raw.Event:
			case <-ctx.Done():
				return
			}
		}
	}
}

func (n *Normalizer) normalize(raw *pipeline.RawEvent) {
	cn := n.profiles[raw.Profile]

	jsonVal := tryDecodeJSON(raw.Event.Raw)

	if cn != nil && len(cn.attributes) > 0 {
		applyAttributeExtractors(cn.attributes, jsonVal, raw.Event, n.log)
	}

	tplCtx := map[string]interface{}{
		"Source":     raw.Event.Source,
		"Entity":     raw.Event.Entity,
		"Attributes": raw.Event.Attributes,
		"Timestamp":  raw.Event.Timestamp,
	}
	if jsonVal != nil {
		tplCtx["json"] = jsonVal
	}

	if cn != nil && cn.topicTpl != nil {
		var buf bytes.Buffer
		if err := cn.topicTpl.Execute(&buf, tplCtx); err == nil && buf.Len() > 0 {
			raw.Event.Topic = buf.String()
		}
	}
	if raw.Event.Topic == "" {
		raw.Event.Topic = defaultTopic(raw)
	}

	if cn != nil && cn.urgencyJSON != "" && jsonVal != nil {
		if s, ok := jsonpath.GetString(jsonVal, cn.urgencyJSON); ok {
			if mapped, ok := cn.urgencyMap[strings.ToUpper(s)]; ok {
				raw.Event.Urgency = mapped
			}
		}
	}
	if raw.Event.Urgency == "" {
		raw.Event.Urgency = defaultUrgency(raw)
	}
}

func applyAttributeExtractors(extractors map[string]config.AttributeExtractor, jsonVal interface{}, ev *event.Event, log *slog.Logger) {
	for key, ex := range extractors {
		if existing := ev.Attributes[key]; existing != "" {
			continue
		}
		switch {
		case ex.Static != "":
			ev.Attributes[key] = ex.Static
		case ex.FromField != "":
			if v := ev.Attributes[ex.FromField]; v != "" {
				ev.Attributes[key] = v
			}
		case ex.FromJSON != "":
			if jsonVal == nil {
				log.Debug("attribute extractor: no JSON to extract from",
					"key", key, "path", ex.FromJSON)
				continue
			}
			if s, ok := jsonpath.GetString(jsonVal, ex.FromJSON); ok && s != "" {
				ev.Attributes[key] = s
			} else {
				log.Debug("attribute extractor: path miss",
					"key", key, "path", ex.FromJSON)
			}
		}
	}
}

func defaultTopic(raw *pipeline.RawEvent) string {
	if raw.Event.Attributes["syslog_malformed"] == "true" {
		return "syslog-malformed"
	}
	if isSyslogSource(raw.Event.Source) {
		if app := raw.Event.Attributes["app"]; app != "" {
			return "syslog-" + app
		}
		return "syslog"
	}
	return "unclassified"
}

func defaultUrgency(raw *pipeline.RawEvent) event.Urgency {
	sev := raw.Event.Attributes["syslog_severity"]
	switch sev {
	case "0", "1", "2":
		return event.UrgencyCritical
	case "3":
		return event.UrgencyHigh
	case "4":
		return event.UrgencyMedium
	case "5":
		return event.UrgencyLow
	case "6", "7":
		return event.UrgencyInfo
	}
	return event.UrgencyInfo
}

func tryDecodeJSON(raw []byte) interface{} {
	if len(raw) == 0 || (raw[0] != '{' && raw[0] != '[') {
		return nil
	}
	var v interface{}
	if err := json.Unmarshal(raw, &v); err != nil {
		return nil
	}
	return v
}
