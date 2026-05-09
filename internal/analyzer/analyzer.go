package analyzer

import (
	"fmt"
	"time"

	"github.com/scuq/notrouter/internal/dedup"
	"github.com/scuq/notrouter/internal/event"
	"github.com/scuq/notrouter/internal/router"
	"github.com/scuq/notrouter/internal/suppress"
)

// Analyzer runs read-only "what would happen" analysis against the live
// router/suppressor/dedup state. Used by the admin UI replay tool to
// debug routing decisions without firing actual events.
//
// Mutability rules:
//   - The analyzer NEVER mutates dedup state (so analyzing doesn't poison
//     the seen-recently cache)
//   - The analyzer NEVER applies suppression rate-limit logging
//   - The analyzer is safe to call from any goroutine
//
// Concurrency: all components held by the analyzer are themselves safe
// for concurrent reads. The analyzer takes only reference snapshots
// of the pipeline components at construction time.
type Analyzer struct {
	router     *router.Router
	suppressor *suppress.Suppressor
	dedup      *dedup.Deduplicator
}

// New builds an analyzer pointing at the live pipeline components. The
// components themselves are NOT cloned - the analyzer reads their config
// state for analysis. Lifetime of the analyzer should match the lifetime
// of the pipeline components.
func New(r *router.Router, s *suppress.Suppressor, d *dedup.Deduplicator) *Analyzer {
	return &Analyzer{
		router:     r,
		suppressor: s,
		dedup:      d,
	}
}

// AnalysisResult is the structured response returned by Analyze.
// Designed to be JSON-encodable for the /admin/api/routing/analyze
// endpoint.
type AnalysisResult struct {
	// Event echoes the input event (post-normalization in the case of
	// audit-log replay) so the UI can confirm what was analyzed.
	Event AnalyzedEvent `json:"event"`

	// SuppressionResult tells operators whether the event would be
	// suppressed by an active suppressor rule. If suppressed, the event
	// would never reach routing.
	Suppression SuppressionAnalysis `json:"suppression"`

	// DedupStatus reports whether the dedup cache currently has a
	// matching key. Read-only check - does NOT add to cache.
	Dedup DedupAnalysis `json:"dedup"`

	// RoutingResult tells operators which routing rules matched, what
	// groups expanded to, and the final subscriber list.
	Routing RoutingAnalysis `json:"routing"`

	// FinalSubscribers is the list of plugin instances that would
	// actually receive the event after suppress + dedup + route. Empty
	// if suppressed or deduped.
	FinalSubscribers []string `json:"final_subscribers"`
}

// AnalyzedEvent is a minimal event projection for the result. We don't
// embed the full event.Event to avoid leaking internal types into the
// API response shape.
type AnalyzedEvent struct {
	Source     string            `json:"source"`
	Entity     string            `json:"entity"`
	Topic      string            `json:"topic"`
	Urgency    string            `json:"urgency"`
	Timestamp  time.Time         `json:"timestamp"`
	Attributes map[string]string `json:"attributes"`
}

type SuppressionAnalysis struct {
	Suppressed     bool   `json:"suppressed"`
	MatchedRule    string `json:"matched_rule,omitempty"`
	MatchedRuleIdx int    `json:"matched_rule_idx,omitempty"`
}

type DedupAnalysis struct {
	WouldBeDeduped bool      `json:"would_be_deduped"`
	Key            string    `json:"key"`
	LastSeenAt     time.Time `json:"last_seen_at,omitempty"`
}

type RoutingAnalysis struct {
	Rules            []RuleAnalysis      `json:"rules"`
	GroupsResolved   map[string][]string `json:"groups_resolved"`
	ResolvedGroupSet []string            `json:"resolved_group_set"`
}

type RuleAnalysis struct {
	Index         int      `json:"index"`
	Description   string   `json:"description"`
	Matched       bool     `json:"matched"`
	GroupsAdded   []string `json:"groups_added,omitempty"`
}

// Analyze runs the event through suppression -> dedup -> routing in
// dry-run mode and returns the full decision trace.
func (a *Analyzer) Analyze(ev *event.Event) AnalysisResult {
	res := AnalysisResult{
		Event: AnalyzedEvent{
			Source:     ev.Source,
			Entity:     ev.Entity,
			Topic:      ev.Topic,
			Urgency:    string(ev.Urgency),
			Timestamp:  ev.Timestamp,
			Attributes: ev.Attributes,
		},
	}

	// === Phase 1: suppression ===
	if a.suppressor != nil {
		idx, name := a.suppressor.AnalyzeMatch(ev, time.Now())
		if idx >= 0 {
			res.Suppression.Suppressed = true
			res.Suppression.MatchedRule = name
			res.Suppression.MatchedRuleIdx = idx
		}
	}

	// === Phase 2: dedup (read-only check) ===
	if a.dedup != nil {
		key, isDup, lastSeen := a.dedup.AnalyzeKey(ev)
		res.Dedup.Key = key
		res.Dedup.WouldBeDeduped = isDup
		if isDup {
			res.Dedup.LastSeenAt = lastSeen
		}
	}

	// === Phase 3: routing (always analyze, even if suppressed/deduped,
	// because operator wants to know "what WOULD have happened") ===
	if a.router != nil {
		ruleResults, groupsResolved := a.router.AnalyzeRouting(ev)
		res.Routing.Rules = make([]RuleAnalysis, len(ruleResults))
		for i, rr := range ruleResults {
			res.Routing.Rules[i] = RuleAnalysis{
				Index:       i,
				Description: rr.Description,
				Matched:     rr.Matched,
				GroupsAdded: rr.GroupsAdded,
			}
		}
		res.Routing.GroupsResolved = groupsResolved

		// Build the deduped resolved-group list (group names that fired).
		groupNames := make([]string, 0, len(groupsResolved))
		for g := range groupsResolved {
			groupNames = append(groupNames, g)
		}
		res.Routing.ResolvedGroupSet = groupNames

		// Final subscribers: union of all subscribers from matched groups,
		// minus any that are blocked by suppression/dedup. We report what
		// WOULD have been delivered if the event flowed through. A
		// suppressed/deduped event has no final subscribers.
		if !res.Suppression.Suppressed && !res.Dedup.WouldBeDeduped {
			subs := make(map[string]struct{})
			for _, gSubs := range groupsResolved {
				for _, s := range gSubs {
					subs[s] = struct{}{}
				}
			}
			res.FinalSubscribers = make([]string, 0, len(subs))
			for s := range subs {
				res.FinalSubscribers = append(res.FinalSubscribers, s)
			}
		} else {
			res.FinalSubscribers = []string{}
		}
	}

	return res
}

// EventFromAuditEntry reconstructs an event.Event from a JSON audit log
// record (parsed). Used by the audit-replay endpoint - we don't have the
// original *event.Event in memory after dispatch, so we rebuild from the
// audit log JSON.
func EventFromAuditEntry(entry map[string]interface{}) (*event.Event, error) {
	ev := &event.Event{
		Attributes: make(map[string]string),
	}

	if v, ok := entry["source"].(string); ok {
		ev.Source = v
	}
	if v, ok := entry["entity"].(string); ok {
		ev.Entity = v
	}
	if v, ok := entry["topic"].(string); ok {
		ev.Topic = v
	}
	if v, ok := entry["urgency"].(string); ok {
		ev.Urgency = event.Urgency(v)
	}
	if v, ok := entry["id"].(string); ok {
		ev.ID = v
	}
	if v, ok := entry["timestamp"].(string); ok {
		if t, err := time.Parse(time.RFC3339Nano, v); err == nil {
			ev.Timestamp = t
		}
	}

	if attrsRaw, ok := entry["attributes"].(map[string]interface{}); ok {
		for k, v := range attrsRaw {
			if s, ok := v.(string); ok {
				ev.Attributes[k] = s
			} else if v != nil {
				// Coerce non-string to JSON-ish string. Audit logs
				// typically have all-string attributes but defensive
				// conversion catches edge cases.
				ev.Attributes[k] = fmt.Sprintf("%v", v)
			}
		}
	}

	if ev.Topic == "" && ev.Entity == "" {
		return nil, fmt.Errorf("audit entry has neither topic nor entity - cannot reconstruct event")
	}
	if ev.Timestamp.IsZero() {
		ev.Timestamp = time.Now()
	}

	return ev, nil
}
