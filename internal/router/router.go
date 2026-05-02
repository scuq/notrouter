package router

import (
	"context"
	"log/slog"
	"path"
	"time"

	"github.com/scuq/notrouter/internal/config"
	"github.com/scuq/notrouter/internal/metrics"
	"github.com/scuq/notrouter/internal/silence"
	"github.com/scuq/notrouter/internal/sink"
	"github.com/scuq/notrouter/internal/source"
)

type Route struct {
	TopicPattern string
	MinSeverity  string
	Workers      []*sink.Worker
	dedup        *dedup
	limiter      *tokenBucket
	grouper      *Grouper
}

type Router struct {
	routes      []Route
	fallback    []*sink.Worker
	log         *slog.Logger
	metrics     *metrics.Metrics
	silences    *silence.Store
	drainWindow time.Duration
	flushTick   time.Duration
}

func New(log *slog.Logger, m *metrics.Metrics, fallback []*sink.Worker, routes ...Route) *Router {
	if log == nil {
		log = slog.Default()
	}
	if m == nil {
		m = metrics.New()
	}
	return &Router{
		routes:      routes,
		fallback:    fallback,
		log:         log,
		metrics:     m,
		drainWindow: 5 * time.Second,
		flushTick:   100 * time.Millisecond,
	}
}

func (r *Router) SetSilences(s *silence.Store) { r.silences = s }

func (r *Router) Run(ctx context.Context, src source.Source) error {
	defer src.Close()
	events := src.Events()

	var ticker *time.Ticker
	var tickC <-chan time.Time
	if r.hasGroupers() {
		ticker = time.NewTicker(r.flushTick)
		tickC = ticker.C
		defer ticker.Stop()
	}

	for {
		select {
		case <-ctx.Done():
			r.flushAllGroupers()
			r.drain(events)
			return nil
		case ev, ok := <-events:
			if !ok {
				r.flushAllGroupers()
				return nil
			}
			r.dispatch(ev)
		case <-tickC:
			r.flushExpiredGroupers()
		}
	}
}

func (r *Router) drain(events <-chan source.Event) {
	deadline := time.NewTimer(r.drainWindow)
	defer deadline.Stop()
	drained := 0
	for {
		select {
		case ev, ok := <-events:
			if !ok {
				if drained > 0 {
					r.log.Info("router drained pending events", "count", drained)
				}
				return
			}
			r.dispatch(ev)
			drained++
		case <-deadline.C:
			r.log.Warn("router drain window expired", "drained", drained)
			return
		}
	}
}

func (r *Router) hasGroupers() bool {
	for _, rt := range r.routes {
		if rt.grouper != nil {
			return true
		}
	}
	return false
}

func (r *Router) flushExpiredGroupers() {
	for _, rt := range r.routes {
		if rt.grouper != nil {
			rt.grouper.FlushExpired()
		}
	}
}

func (r *Router) flushAllGroupers() {
	for _, rt := range r.routes {
		if rt.grouper != nil {
			rt.grouper.FlushAll()
		}
	}
}

func (r *Router) dispatch(ev source.Event) {
	if r.silences != nil && r.silences.Silenced(ev.Topic) {
		r.metrics.Silenced(ev.Topic)
		return
	}
	matched := false
	for _, rt := range r.routes {
		if !match(rt.TopicPattern, ev.Topic) {
			continue
		}
		if !config.SeverityAtLeast(ev.Severity, rt.MinSeverity) {
			continue
		}
		if rt.dedup != nil && !rt.dedup.Allow(ev.Topic+"\x00"+ev.Message) {
			r.metrics.Deduped(rt.TopicPattern)
			matched = true
			continue
		}
		if rt.limiter != nil && !rt.limiter.Allow() {
			r.metrics.RateLimited(rt.TopicPattern)
			matched = true
			continue
		}
		matched = true
		if rt.grouper != nil {
			if err := rt.grouper.Add(ev); err != nil {
				r.log.Error("grouper add failed", "route", rt.TopicPattern, "err", err)
			}
			continue
		}
		for _, w := range rt.Workers {
			w.Submit(ev)
		}
	}
	if !matched {
		if len(r.fallback) == 0 {
			r.metrics.Unmatched()
			return
		}
		for _, w := range r.fallback {
			w.Submit(ev)
		}
	}
}

func match(pattern, topic string) bool {
	if pattern == "" || pattern == "*" {
		return true
	}
	ok, err := path.Match(pattern, topic)
	return err == nil && ok
}
