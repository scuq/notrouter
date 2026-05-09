package suppress

import (
	"context"
	"log/slog"
	"sync"
	"time"

	"github.com/scuq/notrouter/internal/config"
	"github.com/scuq/notrouter/internal/event"
	"github.com/scuq/notrouter/internal/metrics"
	"github.com/scuq/notrouter/internal/pipeline"
)

type rule struct {
	name      string
	predicate *pipeline.Predicate
}

type Suppressor struct {
	in       <-chan *event.Event
	out      chan<- *event.Event
	rules    []rule
	throttle time.Duration
	log      *slog.Logger

	mu      sync.Mutex
	lastLog map[string]time.Time
}

func New(in <-chan *event.Event, out chan<- *event.Event, cfgs []config.SuppressorConfig, throttle time.Duration, log *slog.Logger) (*Suppressor, error) {
	s := &Suppressor{
		in:       in,
		out:      out,
		throttle: throttle,
		log:      log,
		lastLog:  make(map[string]time.Time),
	}
	for _, c := range cfgs {
		p, err := pipeline.CompilePredicate(c.Match, c.Active)
		if err != nil {
			return nil, err
		}
		s.rules = append(s.rules, rule{name: c.Name, predicate: p})
		// Pre-register the metric so it shows up at zero before first hit.
		metrics.Suppressed.WithLabelValues(c.Name)
	}
	return s, nil
}

func (s *Suppressor) Name() string { return "suppressor" }

func (s *Suppressor) Run(ctx context.Context, wg *sync.WaitGroup) {
	defer wg.Done()
	defer close(s.out)

	for {
		select {
		case <-ctx.Done():
			return
		case ev, ok := <-s.in:
			if !ok {
				return
			}
			if name, dropped := s.check(ev); dropped {
				metrics.Suppressed.WithLabelValues(name).Inc()
				s.maybeLog(name, ev)
				continue
			}
			select {
			case s.out <- ev:
			case <-ctx.Done():
				return
			}
		}
	}
}

func (s *Suppressor) check(ev *event.Event) (string, bool) {
	now := time.Now()
	for _, r := range s.rules {
		if r.predicate.Matches(ev, now) {
			return r.name, true
		}
	}
	return "", false
}

func (s *Suppressor) maybeLog(rule string, ev *event.Event) {
	now := time.Now()
	s.mu.Lock()
	last, ok := s.lastLog[rule]
	if ok && now.Sub(last) < s.throttle {
		s.mu.Unlock()
		return
	}
	s.lastLog[rule] = now
	s.mu.Unlock()

	s.log.Info("suppressed",
		"rule", rule,
		"entity", ev.Entity,
		"topic", ev.Topic,
		"urgency", ev.Urgency)
}

// AnalyzeMatch returns the index of the first suppressor rule that
// matches the given event, or (-1, "") if none match. READ-ONLY: does
// not log or rate-limit anything. Used by the analyzer.
func (s *Suppressor) AnalyzeMatch(ev *event.Event, now time.Time) (int, string) {
	for i, r := range s.rules {
		if r.predicate.Matches(ev, now) {
			return i, r.name
		}
	}
	return -1, ""
}
