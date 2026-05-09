package router

import (
	"time"
	"strings"
	"context"
	"log/slog"
	"sync"

	"github.com/scuq/notrouter/internal/config"
	"github.com/scuq/notrouter/internal/event"
	"github.com/scuq/notrouter/internal/metrics"
	"github.com/scuq/notrouter/internal/pipeline"
)

type rule struct {
	predicate *pipeline.Predicate
	groups    []string
}

type Router struct {
	in     <-chan *event.Event
	out    chan<- *pipeline.RoutedEvent
	rules  []rule
	groups map[string]config.GroupConfig
	log    *slog.Logger
}

func New(in <-chan *event.Event, out chan<- *pipeline.RoutedEvent, cfgs []config.RoutingRuleConfig, groups map[string]config.GroupConfig, log *slog.Logger) (*Router, error) {
	r := &Router{in: in, out: out, groups: groups, log: log}
	for _, c := range cfgs {
		p, err := pipeline.CompilePredicate(c.Match, nil)
		if err != nil {
			return nil, err
		}
		r.rules = append(r.rules, rule{predicate: p, groups: c.Groups})
	}
	return r, nil
}

func (r *Router) Name() string { return "router" }

func (r *Router) Run(ctx context.Context, wg *sync.WaitGroup) {
	defer wg.Done()
	defer close(r.out)

	for {
		select {
		case <-ctx.Done():
			return
		case ev, ok := <-r.in:
			if !ok {
				return
			}
			subs := r.resolve(ev)
			if len(subs) == 0 {
				metrics.EventsDropped.WithLabelValues("no_subscribers").Inc()
				r.log.Debug("no subscribers", "entity", ev.Entity, "topic", ev.Topic)
				continue
			}
			select {
			case r.out <- &pipeline.RoutedEvent{Event: ev, Subscribers: subs}:
			case <-ctx.Done():
				return
			}
		}
	}
}

func (r *Router) resolve(ev *event.Event) []string {
	matchedGroups := make(map[string]struct{})
	for _, rule := range r.rules {
		if rule.predicate.Matches(ev, ev.Timestamp) {
			for _, g := range rule.groups {
				matchedGroups[g] = struct{}{}
			}
		}
	}
	subs := make(map[string]struct{})
	for g := range matchedGroups {
		group, ok := r.groups[g]
		if !ok {
			continue
		}
		for _, sub := range group.Subscribers {
			subs[sub] = struct{}{}
		}
	}
	if len(subs) == 0 {
		return nil
	}
	out := make([]string, 0, len(subs))
	for s := range subs {
		out = append(out, s)
	}
	return out
}

// RuleAnalysisResult is the per-rule outcome of routing analysis.
// Returned in evaluation order (same order as the YAML config).
type RuleAnalysisResult struct {
	Description string
	Matched     bool
	GroupsAdded []string
}

// AnalyzeRouting runs the routing matcher in dry-run mode and returns
// per-rule decisions plus the resolved groups-to-subscribers map.
// Read-only: does not enqueue or dispatch the event.
func (r *Router) AnalyzeRouting(ev *event.Event) ([]RuleAnalysisResult, map[string][]string) {
	results := make([]RuleAnalysisResult, len(r.rules))
	matchedGroups := make(map[string]struct{})
	now := ev.Timestamp
	if now.IsZero() {
		now = time.Now()
	}

	for i, rule := range r.rules {
		matched := rule.predicate.Matches(ev, now)
		desc := describePredicate(rule.predicate, rule.groups)
		results[i] = RuleAnalysisResult{
			Description: desc,
			Matched:     matched,
		}
		if matched {
			results[i].GroupsAdded = append([]string(nil), rule.groups...)
			for _, g := range rule.groups {
				matchedGroups[g] = struct{}{}
			}
		}
	}

	groupsResolved := make(map[string][]string, len(matchedGroups))
	for g := range matchedGroups {
		gc, ok := r.groups[g]
		if !ok {
			groupsResolved[g] = nil
			continue
		}
		groupsResolved[g] = append([]string(nil), gc.Subscribers...)
	}

	return results, groupsResolved
}

// describePredicate produces a human-readable summary for the analyzer.
// Best-effort - not a stable serialization format.
func describePredicate(p *pipeline.Predicate, groups []string) string {
	desc := p.Describe()
	if desc == "" {
		desc = "(catch-all)"
	}
	if len(groups) > 0 {
		return desc + " -> [" + strings.Join(groups, ", ") + "]"
	}
	return desc
}

