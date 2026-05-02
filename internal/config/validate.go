package config

import (
	"errors"
	"fmt"
	"path"
	"time"
)

func pathMatchValid(pattern string) (bool, error) {
	_, err := path.Match(pattern, "")
	return err == nil, err
}

func (c *Config) Validate() error {
	var errs []error

	sinkNames := make(map[string]bool, len(c.Sinks))
	for i, s := range c.Sinks {
		if s.Name == "" {
			errs = append(errs, fmt.Errorf("sinks[%d]: name required", i))
		}
		if s.Type == "" {
			errs = append(errs, fmt.Errorf("sinks[%d] %q: type required", i, s.Name))
		}
		if sinkNames[s.Name] {
			errs = append(errs, fmt.Errorf("sinks[%d]: duplicate name %q", i, s.Name))
		}
		sinkNames[s.Name] = true
		switch s.Type {
		case "stdout":
		case "file":
			if s.Path == "" {
				errs = append(errs, fmt.Errorf("sink %q: type=file requires path", s.Name))
			}
		case "webhook":
			if s.URL == "" {
				errs = append(errs, fmt.Errorf("sink %q: type=webhook requires url", s.Name))
			}
		case "smtp":
			if s.SMTPHost == "" {
				errs = append(errs, fmt.Errorf("sink %q: type=smtp requires smtp_host", s.Name))
			}
			if s.From == "" {
				errs = append(errs, fmt.Errorf("sink %q: type=smtp requires from", s.Name))
			}
			if len(s.To) == 0 {
				errs = append(errs, fmt.Errorf("sink %q: type=smtp requires to", s.Name))
			}
		case "":
		default:
			errs = append(errs, fmt.Errorf("sink %q: unknown type %q", s.Name, s.Type))
		}
	}

	sourceNames := make(map[string]bool, len(c.Sources))
	for i, src := range c.Sources {
		if src.Name == "" {
			errs = append(errs, fmt.Errorf("sources[%d]: name required", i))
		}
		if sourceNames[src.Name] {
			errs = append(errs, fmt.Errorf("sources[%d]: duplicate name %q", i, src.Name))
		}
		sourceNames[src.Name] = true
		switch src.Type {
		case "http":
			if (src.TLSCert == "") != (src.TLSKey == "") {
				errs = append(errs, fmt.Errorf("source %q: tls_cert and tls_key must be set together", src.Name))
			}
		case "stdin":
		case "":
			errs = append(errs, fmt.Errorf("source %q: type required", src.Name))
		default:
			errs = append(errs, fmt.Errorf("source %q: unknown type %q", src.Name, src.Type))
		}
		for _, p := range src.AllowedTopics {
			if _, err := pathMatchValid(p); err != nil {
				errs = append(errs, fmt.Errorf("source %q: invalid allowed_topics pattern %q: %w", src.Name, p, err))
			}
		}
	}

	for i, r := range c.Routes {
		if r.Topic == "" {
			errs = append(errs, fmt.Errorf("routes[%d]: topic required", i))
		}
		if len(r.Sinks) == 0 {
			errs = append(errs, fmt.Errorf("route %q: at least one sink required", r.Topic))
		}
		for _, name := range r.Sinks {
			if !sinkNames[name] {
				errs = append(errs, fmt.Errorf("route %q: references unknown sink %q", r.Topic, name))
			}
		}
		if r.MinSeverity != "" {
			if !ValidSeverity(r.MinSeverity) {
				errs = append(errs, fmt.Errorf("route %q: invalid min_severity %q", r.Topic, r.MinSeverity))
			}
		}
		if r.DedupWindow != "" {
			if _, err := time.ParseDuration(r.DedupWindow); err != nil {
				errs = append(errs, fmt.Errorf("route %q: invalid dedup_window %q: %w", r.Topic, r.DedupWindow, err))
			}
		}
		if r.RatePerSec < 0 {
			errs = append(errs, fmt.Errorf("route %q: rate_per_sec must be >= 0", r.Topic))
		}
		if r.RateBurst < 0 {
			errs = append(errs, fmt.Errorf("route %q: rate_burst must be >= 0", r.Topic))
		}
		if r.GroupWindow != "" {
			if _, err := time.ParseDuration(r.GroupWindow); err != nil {
				errs = append(errs, fmt.Errorf("route %q: invalid group_window %q: %w", r.Topic, r.GroupWindow, err))
			}
		}
	}

	return errors.Join(errs...)
}

var severityRank = map[string]int{
	"":         0,
	"debug":    10,
	"info":     20,
	"warning":  30,
	"warn":     30,
	"error":    40,
	"high":     40,
	"critical": 50,
}

func ValidSeverity(s string) bool {
	_, ok := severityRank[s]
	return ok
}

func SeverityAtLeast(have, min string) bool {
	if min == "" {
		return true
	}
	h, ok := severityRank[have]
	if !ok {
		return false
	}
	return h >= severityRank[min]
}
