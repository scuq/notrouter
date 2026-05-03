package admin

import (
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"sync"
	"time"

	"github.com/prometheus/client_golang/prometheus/promhttp"

	"github.com/scuq/notrouter/internal/auth"
	"github.com/scuq/notrouter/internal/version"
)

// QueueDegradedRatio is the threshold at which /healthz reports degraded.
// 0.9 = degraded if any instance queue is >=90% full.
const QueueDegradedRatio = 0.9

type Server struct {
	addr   string
	user   string
	pass   string
	probes Probes
	log    *slog.Logger
	server *http.Server
}

func New(addr, user, pass string, probes Probes, log *slog.Logger) *Server {
	return &Server{addr: addr, user: user, pass: pass, probes: probes, log: log}
}

func (s *Server) Start(ctx context.Context, wg *sync.WaitGroup) error {
	mux := http.NewServeMux()

	// /healthz reports degraded when any per-instance queue is near-full.
	// We pick a hard 90% threshold rather than a moving-average; simple
	// metrics are easier to alert on and easier to reason about.
	mux.HandleFunc("/healthz", s.handleHealthz)

	// /metrics is unauthenticated by convention - Prometheus scrapers
	// shouldn't need credentials and network controls protect it.
	mux.Handle("/metrics", promhttp.Handler())

	// /version is unauthenticated and useful for blue/green deploys to
	// confirm which build is live without poking around the container.
	mux.HandleFunc("/version", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, map[string]string{
			"version": version.Version,
			"commit":  version.Commit,
		})
	})

	// All /admin/* routes require basic auth.
	adminMux := http.NewServeMux()
	adminMux.HandleFunc("/admin/state", s.handleState)
	adminMux.HandleFunc("/admin/deliveries", s.handleDeliveries)
	adminMux.HandleFunc("/admin/dedup/clear", s.handleDedupClear)
	adminMux.HandleFunc("/admin/", s.handleAdminIndex)

	mux.Handle("/admin/", auth.BasicAuth(s.user, s.pass, adminMux))

	// Bare / for backwards compat: simple banner behind auth.
	mux.Handle("/", auth.BasicAuth(s.user, s.pass, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("notrouter admin\n"))
	})))

	s.server = &http.Server{
		Addr:              s.addr,
		Handler:           mux,
		ReadHeaderTimeout: 5 * time.Second,
	}

	wg.Add(1)
	go func() {
		defer wg.Done()
		s.log.Info("admin listening", "addr", s.addr)
		if err := s.server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			s.log.Error("admin server error", "err", err)
		}
	}()

	wg.Add(1)
	go func() {
		defer wg.Done()
		<-ctx.Done()
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = s.server.Shutdown(shutdownCtx)
	}()

	return nil
}

// handleHealthz returns 200 + ok, or 503 + JSON describing what's degraded.
// Three signals can flip to degraded:
//   - any plugin instance queue is >=90% full
//   - the tracker has more than 10000 pending deliveries (something is stuck)
//   - the dedup map has more than 1000000 entries (config bug or memory leak)
func (s *Server) handleHealthz(w http.ResponseWriter, r *http.Request) {
	type queueReport struct {
		QueueState
		Pct float64 `json:"pct"`
	}
	var degraded []string
	var queues []queueReport

	if s.probes.Dispatch != nil {
		for _, q := range s.probes.Dispatch.QueueState() {
			pct := 0.0
			if q.Capacity > 0 {
				pct = float64(q.Depth) / float64(q.Capacity)
			}
			queues = append(queues, queueReport{QueueState: q, Pct: pct})
			if pct >= QueueDegradedRatio {
				degraded = append(degraded, "queue:"+q.Instance)
			}
		}
	}

	pending := 0
	if s.probes.Tracker != nil {
		pending = s.probes.Tracker.Pending()
		if pending > 10000 {
			degraded = append(degraded, "tracker_pending_high")
		}
	}

	dedupSize := 0
	if s.probes.Dedup != nil {
		dedupSize = s.probes.Dedup.Size()
		if dedupSize > 1000000 {
			degraded = append(degraded, "dedup_size_high")
		}
	}

	if len(degraded) == 0 {
		w.Header().Set("Content-Type", "text/plain")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("ok"))
		return
	}

	writeJSON(w, http.StatusServiceUnavailable, map[string]interface{}{
		"status":           "degraded",
		"reasons":          degraded,
		"queues":           queues,
		"tracker_pending":  pending,
		"dedup_size":       dedupSize,
	})
}

// handleState bundles all read-only introspection in one call. Useful for
// diagnostics scripts; keeps each individual endpoint cheap.
func (s *Server) handleState(w http.ResponseWriter, r *http.Request) {
	state := map[string]interface{}{
		"version": map[string]string{
			"version": version.Version,
			"commit":  version.Commit,
		},
	}
	if s.probes.Dispatch != nil {
		state["queues"] = s.probes.Dispatch.QueueState()
	}
	if s.probes.Dedup != nil {
		state["dedup_size"] = s.probes.Dedup.Size()
	}
	if s.probes.Tracker != nil {
		state["tracker_pending"] = s.probes.Tracker.Pending()
	}
	writeJSON(w, http.StatusOK, state)
}

func (s *Server) handleDeliveries(w http.ResponseWriter, r *http.Request) {
	if s.probes.Tracker == nil {
		writeJSON(w, http.StatusOK, map[string]interface{}{"recent": []interface{}{}})
		return
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"pending": s.probes.Tracker.Pending(),
		"recent":  s.probes.Tracker.RecentFinal(),
	})
}

// handleDedupClear is the panic button: after a config rollout that botched
// dedup keys, you want to wipe the in-memory map without a process restart.
// POST only - GET shouldn't have side effects.
func (s *Server) handleDedupClear(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "POST required", http.StatusMethodNotAllowed)
		return
	}
	if s.probes.Dedup == nil {
		http.Error(w, "dedup not available", http.StatusServiceUnavailable)
		return
	}
	before := s.probes.Dedup.Size()
	s.probes.Dedup.Clear()
	s.log.Warn("dedup cleared via admin endpoint", "previous_size", before)
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"cleared": true,
		"previous_size": before,
	})
}

func (s *Server) handleAdminIndex(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/plain")
	w.Write([]byte("notrouter admin\n\nendpoints:\n  GET  /admin/state\n  GET  /admin/deliveries\n  POST /admin/dedup/clear\n"))
}

func writeJSON(w http.ResponseWriter, status int, body interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(body)
}
