package pipeline

import (
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
