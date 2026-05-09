package pipeline

import (
	"strings"
	"fmt"
	"net"
	"regexp"
	"time"

	"github.com/scuq/notrouter/internal/config"
	"github.com/scuq/notrouter/internal/event"
)

type Predicate struct {
	entityRegex  *regexp.Regexp
	entityIPNets []*net.IPNet
	topics       map[string]struct{}
	urgencies    map[event.Urgency]struct{}
	attributes   map[string]string
	activeFrom   *time.Time
	activeUntil  *time.Time
}

func CompilePredicate(m config.MatchConfig, active *config.TimeWindow) (*Predicate, error) {
	p := &Predicate{}

	if m.EntityRegex != "" {
		re, err := regexp.Compile(m.EntityRegex)
		if err != nil {
			return nil, fmt.Errorf("entity_regex: %w", err)
		}
		p.entityRegex = re
	}

	for _, cidr := range m.EntityIPIn {
		_, n, err := net.ParseCIDR(cidr)
		if err != nil {
			return nil, fmt.Errorf("entity_ip_in %q: %w", cidr, err)
		}
		p.entityIPNets = append(p.entityIPNets, n)
	}

	if len(m.Topic) > 0 {
		p.topics = make(map[string]struct{}, len(m.Topic))
		for _, t := range m.Topic {
			p.topics[t] = struct{}{}
		}
	}

	if len(m.Urgency) > 0 {
		p.urgencies = make(map[event.Urgency]struct{}, len(m.Urgency))
		for _, u := range m.Urgency {
			p.urgencies[event.Urgency(u)] = struct{}{}
		}
	}

	if len(m.Attributes) > 0 {
		p.attributes = m.Attributes
	}

	if active != nil {
		p.activeFrom = &active.From
		p.activeUntil = &active.Until
	}

	return p, nil
}

func (p *Predicate) Matches(ev *event.Event, now time.Time) bool {
	if p.activeFrom != nil && now.Before(*p.activeFrom) {
		return false
	}
	if p.activeUntil != nil && now.After(*p.activeUntil) {
		return false
	}
	if p.entityRegex != nil && !p.entityRegex.MatchString(ev.Entity) {
		return false
	}
	if len(p.entityIPNets) > 0 {
		if ev.EntityIP == nil {
			return false
		}
		hit := false
		for _, n := range p.entityIPNets {
			if n.Contains(ev.EntityIP) {
				hit = true
				break
			}
		}
		if !hit {
			return false
		}
	}
	if p.topics != nil {
		if _, ok := p.topics[ev.Topic]; !ok {
			return false
		}
	}
	if p.urgencies != nil {
		if _, ok := p.urgencies[ev.Urgency]; !ok {
			return false
		}
	}
	for k, want := range p.attributes {
		if got, ok := ev.Attributes[k]; !ok || got != want {
			return false
		}
	}
	return true
}

// Describe returns a short human-readable summary of the predicate's
// match conditions. Used by the analyzer for UI labels. Best-effort -
// not a stable serialization format.
func (p *Predicate) Describe() string {
	parts := make([]string, 0, 4)
	if p.entityRegex != nil {
		parts = append(parts, "entity_regex="+p.entityRegex.String())
	}
	if len(p.topics) > 0 {
		topicNames := make([]string, 0, len(p.topics))
		for t := range p.topics {
			topicNames = append(topicNames, t)
		}
		parts = append(parts, "topic in ["+strings.Join(topicNames, ", ")+"]")
	}
	if len(p.urgencies) > 0 {
		uNames := make([]string, 0, len(p.urgencies))
		for u := range p.urgencies {
			uNames = append(uNames, string(u))
		}
		parts = append(parts, "urgency in ["+strings.Join(uNames, ", ")+"]")
	}
	if len(p.attributes) > 0 {
		attrParts := make([]string, 0, len(p.attributes))
		for k, v := range p.attributes {
			attrParts = append(attrParts, k+"="+v)
		}
		parts = append(parts, "attrs("+strings.Join(attrParts, ",")+")")
	}
	if len(p.entityIPNets) > 0 {
		parts = append(parts, fmt.Sprintf("entity_ip_in (%d nets)", len(p.entityIPNets)))
	}
	if len(parts) == 0 {
		return ""
	}
	return strings.Join(parts, " AND ")
}

