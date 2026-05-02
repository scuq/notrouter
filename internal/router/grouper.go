package router

import (
	"bytes"
	"fmt"
	"sync"
	"text/template"
	"time"

	"github.com/scuq/notrouter/internal/sink"
	"github.com/scuq/notrouter/internal/source"
)

// Grouper batches events sharing a key into a single digest event,
// emitted after `window` has elapsed since the first event in the group.
type Grouper struct {
	window  time.Duration
	keyTmpl *template.Template
	workers []*sink.Worker
	now     func() time.Time

	mu     sync.Mutex
	groups map[string]*group
}

type group struct {
	firstSeen time.Time
	count     int
	sample    source.Event
	maxSev    string
}

func newGrouper(window time.Duration, groupBy string, workers []*sink.Worker) (*Grouper, error) {
	if groupBy == "" {
		groupBy = "{{.Topic}}"
	}
	t, err := template.New("group_by").Parse(groupBy)
	if err != nil {
		return nil, fmt.Errorf("group_by template: %w", err)
	}
	return &Grouper{
		window:  window,
		keyTmpl: t,
		workers: workers,
		now:     time.Now,
		groups:  make(map[string]*group),
	}, nil
}

// Add accumulates an event into its group. Returns true if the event was
// the first in its group (the caller may use this to drive flushing).
func (g *Grouper) Add(ev source.Event) error {
	key, err := g.key(ev)
	if err != nil {
		return err
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	gr, ok := g.groups[key]
	if !ok {
		gr = &group{firstSeen: g.now(), sample: ev, maxSev: ev.Severity}
		g.groups[key] = gr
	}
	gr.count++
	if severityRank(ev.Severity) > severityRank(gr.maxSev) {
		gr.maxSev = ev.Severity
	}
	return nil
}

// FlushExpired emits digest events for every group whose window has elapsed.
func (g *Grouper) FlushExpired() {
	now := g.now()
	g.mu.Lock()
	expired := make(map[string]*group)
	for key, gr := range g.groups {
		if now.Sub(gr.firstSeen) >= g.window {
			expired[key] = gr
			delete(g.groups, key)
		}
	}
	g.mu.Unlock()

	for key, gr := range expired {
		g.emit(key, gr)
	}
}

// FlushAll emits all pending groups regardless of age. Used at shutdown.
func (g *Grouper) FlushAll() {
	g.mu.Lock()
	pending := g.groups
	g.groups = make(map[string]*group)
	g.mu.Unlock()
	for key, gr := range pending {
		g.emit(key, gr)
	}
}

func (g *Grouper) emit(key string, gr *group) {
	digest := source.Event{
		Topic:    gr.sample.Topic,
		Message:  fmt.Sprintf("[group %s] %d events; first: %s", key, gr.count, gr.sample.Message),
		Severity: gr.maxSev,
		Time:     gr.firstSeen,
	}
	for _, w := range g.workers {
		w.Submit(digest)
	}
}

func (g *Grouper) key(ev source.Event) (string, error) {
	var buf bytes.Buffer
	if err := g.keyTmpl.Execute(&buf, ev); err != nil {
		return "", err
	}
	return buf.String(), nil
}

// minimal in-tree severity rank for "max severity in group"; mirrors config.severityRank
func severityRank(s string) int {
	switch s {
	case "critical":
		return 50
	case "error", "high":
		return 40
	case "warn", "warning":
		return 30
	case "info":
		return 20
	case "debug":
		return 10
	default:
		return 0
	}
}
