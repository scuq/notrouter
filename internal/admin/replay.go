package admin

import (
	"encoding/json"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/scuq/notrouter/internal/analyzer"
	"github.com/scuq/notrouter/internal/event"
)

// auditAccessor and analysisAccessor are interface-typed dependencies
// so admin doesn't have a hard import on the runtime/router packages
// (which would create import cycles). Set via SetAnalyzer at startup.
type auditAccessor interface {
	ReadRecent(maxEntries int) ([]analyzer.AuditEntry, error)
	FindByID(id string) (analyzer.AuditEntry, error)
}

type analysisAccessor interface {
	Analyze(ev *event.Event) analyzer.AnalysisResult
}

// SetAnalyzer wires in the audit reader + analyzer at server startup.
// Both are optional - if not set, the analyze endpoints return 503.
// nil-safe.
func (s *Server) SetAnalyzer(audit auditAccessor, an analysisAccessor) {
	if s == nil {
		return
	}
	s.rtMu.Lock()
	defer s.rtMu.Unlock()
	s.auditReader = audit
	s.analyzer = an
}

// handleAuditRecent returns the most recent N audit log entries.
//
// GET /admin/api/audit/recent?limit=50&filter=<substring>
//
// limit defaults to 50, max 500. filter is a case-insensitive substring
// match against entity + topic + source. Empty filter returns everything.
func (s *Server) handleAuditRecent(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	s.rtMu.RLock()
	audit := s.auditReader
	s.rtMu.RUnlock()
	if audit == nil {
		http.Error(w, "audit reader not configured", http.StatusServiceUnavailable)
		return
	}

	limit := 50
	if v := r.URL.Query().Get("limit"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			limit = n
			if limit > 500 {
				limit = 500
			}
		}
	}

	entries, err := audit.ReadRecent(limit)
	if err != nil {
		s.log.Warn("audit recent read failed", "err", err)
		http.Error(w, "audit read failed: "+err.Error(), http.StatusInternalServerError)
		return
	}

	// Apply optional filter. Substring match against the JSON-stringified
	// entry's entity, topic, source fields. Cheap and good enough for
	// "find that one event" use cases.
	filter := strings.ToLower(strings.TrimSpace(r.URL.Query().Get("filter")))
	if filter != "" {
		filtered := make([]analyzer.AuditEntry, 0, len(entries))
		for _, e := range entries {
			entity, _ := e["entity"].(string)
			topic, _ := e["topic"].(string)
			source, _ := e["source"].(string)
			combined := strings.ToLower(entity + " " + topic + " " + source)
			if strings.Contains(combined, filter) {
				filtered = append(filtered, e)
			}
		}
		entries = filtered
	}

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"entries": entries,
		"count":   len(entries),
	})
}

// handleRoutingAnalyze runs an event through the analyzer dry-run logic.
// Two body shapes accepted:
//
//   1. Synthetic event:
//      {"event": {"topic": "...", "entity": "...", "attributes": {...}, ...}}
//
//   2. From audit log:
//      {"audit_id": "20260509T084146-0f6509b80b55d594"}
//
// POST /admin/api/routing/analyze
func (s *Server) handleRoutingAnalyze(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	s.rtMu.RLock()
	an := s.analyzer
	audit := s.auditReader
	s.rtMu.RUnlock()
	if an == nil {
		http.Error(w, "analyzer not configured", http.StatusServiceUnavailable)
		return
	}

	var req struct {
		AuditID string `json:"audit_id,omitempty"`
		Event   *struct {
			Source     string            `json:"source"`
			Entity     string            `json:"entity"`
			Topic      string            `json:"topic"`
			Urgency    string            `json:"urgency"`
			Attributes map[string]string `json:"attributes"`
		} `json:"event,omitempty"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "invalid JSON: "+err.Error(), http.StatusBadRequest)
		return
	}

	// Build the event to analyze.
	var ev *event.Event
	if req.AuditID != "" {
		// Audit-log replay path.
		if audit == nil {
			http.Error(w, "audit reader not configured", http.StatusServiceUnavailable)
			return
		}
		entry, err := audit.FindByID(req.AuditID)
		if err != nil {
			http.Error(w, "audit lookup failed: "+err.Error(), http.StatusNotFound)
			return
		}
		built, err := analyzer.EventFromAuditEntry(entry)
		if err != nil {
			http.Error(w, "audit entry malformed: "+err.Error(), http.StatusUnprocessableEntity)
			return
		}
		ev = built
	} else if req.Event != nil {
		// Synthetic event path.
		ev = &event.Event{
			Source:     req.Event.Source,
			Entity:     req.Event.Entity,
			Topic:      req.Event.Topic,
			Urgency:    event.Urgency(req.Event.Urgency),
			Timestamp:  time.Now(),
			Attributes: req.Event.Attributes,
		}
		if ev.Attributes == nil {
			ev.Attributes = make(map[string]string)
		}
	} else {
		http.Error(w, "request must specify either audit_id or event", http.StatusBadRequest)
		return
	}

	result := an.Analyze(ev)
	writeJSON(w, http.StatusOK, result)
}
