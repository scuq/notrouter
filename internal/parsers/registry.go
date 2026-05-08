package parsers

import (
	"fmt"
	"log/slog"
	"strings"

	"github.com/scuq/notrouter/internal/config"
	"github.com/scuq/notrouter/internal/event"
)

// Parser inspects an event and may transform it. Used by the SMTP receiver
// to apply vendor-specific extraction (CheckMK, Grafana, etc.) before the
// event enters the pipeline.
//
// Lifecycle:
//   1. Match() decides whether this parser handles the event.
//   2. If Match returns true, Parse() runs and may set additional
//      attributes on ev.
//   3. The parser returns the profile name (e.g. "checkmk") that the
//      pipeline should use for further normalization.
//
// Parsers MUST NOT block on I/O - they run synchronously on the receiver
// goroutine. Pure in-memory regex/template work only.
type Parser interface {
	Name() string
	Match(ev *event.Event) bool
	Parse(ev *event.Event) (profileName string, err error)
}

// Registry holds parsers in their configured (priority) order. First
// matching parser wins. Built from config at startup.
type Registry struct {
	parsers          []Parser
	fallbackProfile  string
	log              *slog.Logger
}

// NewRegistry compiles parser configs into runtime parsers. Returns nil
// if no parsers are configured (callers can skip dispatch entirely).
//
// Strict validation: any malformed regex, template, or unknown extractor
// type fails at load time. Operators see the error before notrouter starts
// taking traffic - much better than discovering at runtime that the parser
// silently does nothing.
func NewRegistry(cfgs []config.ParserConfig, log *slog.Logger) (*Registry, error) {
	if len(cfgs) == 0 {
		return nil, nil
	}

	r := &Registry{
		fallbackProfile: "smtp_generic",
		log:             log,
		parsers:         make([]Parser, 0, len(cfgs)),
	}

	for _, c := range cfgs {
		if c.Name == "" {
			return nil, fmt.Errorf("mail parser entry has no name")
		}
		p, err := newConfigDrivenParser(c, log)
		if err != nil {
			return nil, fmt.Errorf("parser %q: %w", c.Name, err)
		}
		r.parsers = append(r.parsers, p)
	}

	names := make([]string, 0, len(r.parsers))
	for _, p := range r.parsers {
		names = append(names, p.Name())
	}
	log.Info("mail parsers loaded",
		"count", len(r.parsers),
		"order", strings.Join(names, ","),
		"fallback_profile", r.fallbackProfile)
	return r, nil
}

// Dispatch tries each parser in order. Returns the profile name from the
// first parser whose Match() succeeds and Parse() completes without
// error. Falls back to "smtp_generic" if no parser matched OR if a
// parser matched but failed to parse.
//
// nil-safe: returns the fallback profile when r is nil (no parsers
// configured). Lets receivers call this unconditionally.
func (r *Registry) Dispatch(ev *event.Event) string {
	if r == nil {
		return "smtp_generic"
	}

	for _, p := range r.parsers {
		if !p.Match(ev) {
			continue
		}
		profile, err := p.Parse(ev)
		if err != nil {
			r.log.Warn("parser failed; falling back to smtp_generic",
				"parser", p.Name(),
				"err", err,
				"subject", ev.Attributes["subject"],
				"from", ev.Attributes["from_address"])
			return r.fallbackProfile
		}
		return profile
	}

	// No parser matched - fallback. This is normal for emails from
	// senders we haven't built a parser for yet.
	return r.fallbackProfile
}
