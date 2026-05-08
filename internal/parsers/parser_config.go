package parsers

import (
	"fmt"
	"log/slog"
	"strings"

	"github.com/scuq/notrouter/internal/config"
	"github.com/scuq/notrouter/internal/event"
)

// configDrivenParser implements Parser using a YAML-defined sequence of
// extractors. The whole framework is one struct because the only thing
// that varies between vendors (CheckMK, Grafana, Palo Alto, etc.) is the
// extractor configuration.
//
// Concurrency: parsers run on the receiver goroutine. Match/Parse are
// stateless (no mutation of the parser itself). Compiled extractors are
// safe for concurrent use because Go's regexp.Regexp and template.Template
// are documented as concurrent-safe after compilation.
type configDrivenParser struct {
	name            string
	profile         string
	subjectPrefix   string
	rcptToContains  string // optional: match by recipient address fragment
	extractors      []compiledExtractor
	log             *slog.Logger
}

func newConfigDrivenParser(c config.ParserConfig, log *slog.Logger) (*configDrivenParser, error) {
	if c.Profile == "" {
		return nil, fmt.Errorf("parser %q: profile is required", c.Name)
	}

	p := &configDrivenParser{
		name:           c.Name,
		profile:        c.Profile,
		subjectPrefix:  c.Match.SubjectPrefix,
		rcptToContains: c.Match.RcptToContains,
		log:            log,
	}

	// Compile all extractors at config-load time. Bad regex / bad
	// template = startup failure, NOT silent runtime no-op.
	for i, ec := range c.Extract {
		comp, err := compileExtractor(ec)
		if err != nil {
			return nil, fmt.Errorf("parser %q extractor #%d (type=%q): %w",
				c.Name, i+1, ec.Type, err)
		}
		p.extractors = append(p.extractors, comp)
	}

	if len(p.extractors) == 0 {
		log.Warn("parser has no extractors - it will set the profile but extract nothing",
			"parser", c.Name)
	}

	return p, nil
}

func (p *configDrivenParser) Name() string { return p.name }

// Match returns true if this parser should handle the event. We use
// SUBJECT prefix as the primary discriminator because it's stable
// across vendor versions and trivially fast to check.
//
// Operators can also match by RCPT TO substring if needed (e.g., a
// vendor that sends to a specific dedicated address).
func (p *configDrivenParser) Match(ev *event.Event) bool {
	if p.subjectPrefix != "" {
		subj := ev.Attributes["subject"]
		if !strings.HasPrefix(subj, p.subjectPrefix) {
			return false
		}
	}
	if p.rcptToContains != "" {
		rcpt := ev.Attributes["to_address"]
		if !strings.Contains(rcpt, p.rcptToContains) {
			return false
		}
	}
	// At least one match condition must be configured (validated at
	// load time). If we got here, all configured conditions passed.
	return p.subjectPrefix != "" || p.rcptToContains != ""
}

// Parse runs all extractors in sequence. Each extractor may set
// attributes that later extractors can read - that's how computed
// fields work (e.g., extract event_raw with kvline, then derive state
// from event_raw with regex).
//
// An extractor returning an error here is unusual - it means something
// at runtime went wrong (template execution failed on this specific
// input, etc.). We return the error so Dispatch can log + fall back.
//
// An extractor finding no match (regex didn't apply) is normal - it
// sets nothing and we move on. No error.
func (p *configDrivenParser) Parse(ev *event.Event) (string, error) {
	for i, ex := range p.extractors {
		if err := ex.apply(ev); err != nil {
			return "", fmt.Errorf("extractor #%d (%s): %w", i+1, ex.kind(), err)
		}
	}
	return p.profile, nil
}
