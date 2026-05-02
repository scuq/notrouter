package router

import (
	"fmt"
	"log/slog"
	"time"

	"github.com/scuq/notrouter/internal/config"
	"github.com/scuq/notrouter/internal/metrics"
	"github.com/scuq/notrouter/internal/sink"
)

func Build(log *slog.Logger, m *metrics.Metrics, cfg *config.Config, workersByName map[string]*sink.Worker) (*Router, error) {
	routes := make([]Route, 0, len(cfg.Routes))
	for _, rc := range cfg.Routes {
		ws := make([]*sink.Worker, 0, len(rc.Sinks))
		for _, name := range rc.Sinks {
			w, ok := workersByName[name]
			if !ok {
				return nil, fmt.Errorf("route %q references unknown sink %q", rc.Topic, name)
			}
			ws = append(ws, w)
		}
		route := Route{
			TopicPattern: rc.Topic,
			MinSeverity:  rc.MinSeverity,
			Workers:      ws,
		}
		if rc.DedupWindow != "" {
			d, err := time.ParseDuration(rc.DedupWindow)
			if err != nil {
				return nil, fmt.Errorf("route %q: dedup_window: %w", rc.Topic, err)
			}
			route.dedup = newDedup(d)
		}
		if rc.RatePerSec > 0 {
			route.limiter = newTokenBucket(rc.RatePerSec, rc.RateBurst)
		}
		if rc.GroupWindow != "" {
			win, err := time.ParseDuration(rc.GroupWindow)
			if err != nil {
				return nil, fmt.Errorf("route %q: group_window: %w", rc.Topic, err)
			}
			gr, err := newGrouper(win, rc.GroupBy, ws)
			if err != nil {
				return nil, fmt.Errorf("route %q: %w", rc.Topic, err)
			}
			route.grouper = gr
		}
		routes = append(routes, route)
	}

	var fallback []*sink.Worker
	if len(routes) == 0 {
		for _, w := range workersByName {
			fallback = append(fallback, w)
		}
	}
	return New(log, m, fallback, routes...), nil
}
