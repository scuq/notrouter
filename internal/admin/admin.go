package admin

import (
	"context"
	"crypto/subtle"
	"encoding/json"
	"log/slog"
	"net/http"
	"sync"
	"time"

	"github.com/prometheus/client_golang/prometheus/promhttp"

	"github.com/scuq/notrouter/internal/version"
)

const QueueDegradedRatio = 0.9

type Server struct {
	addr    string
	user    string
	pass    string
	creds   credsAccessor
	probes  Probes
	log     *slog.Logger
	server  *http.Server
	store   *SessionStore
	uiH     *uiHandler
}

// NewWithUI is the new constructor used in pass 5a. Takes the credentials
// store and session TTL so the UI can do real auth. The legacy `New(...)`
// signature is kept as a thin wrapper so older code compiles unchanged
// during the upgrade.
func NewWithUI(addr string, basicUser, basicPass string, creds credsAccessor, sessionTTL time.Duration, probes Probes, log *slog.Logger) (*Server, error) {
	store := NewSessionStore(sessionTTL)
	uiH, err := newUIHandler(store, creds, probes, sessionTTL, log)
	if err != nil {
		return nil, err
	}
	return &Server{
		addr:   addr,
		user:   basicUser,
		pass:   basicPass,
		creds:  creds,
		probes: probes,
		log:    log,
		store:  store,
		uiH:    uiH,
	}, nil
}

func (s *Server) Start(ctx context.Context, wg *sync.WaitGroup) error {
	mux := http.NewServeMux()

	// Public endpoints (no auth).
	mux.HandleFunc("/healthz", s.handleHealthz)
	mux.Handle("/metrics", promhttp.Handler())
	mux.HandleFunc("/version", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, map[string]string{
			"version": version.Version,
			"commit":  version.Commit,
		})
	})

	// Web UI (session-cookie auth).
	s.uiH.register(mux)

	// Legacy admin JSON endpoints accept basic auth OR session cookie.
	// Existing scripts using -u admin:pass keep working; the UI's session
	// cookie also unlocks them. New code should prefer /admin/api/*.
	dual := s.dualAuth(http.HandlerFunc(s.handleLegacyMux))
	mux.Handle("/admin/state", dual)
	mux.Handle("/admin/deliveries", dual)
	mux.Handle("/admin/dedup/clear", dual)
	mux.Handle("/admin/", dual)

	// Bare / behind dual auth, simple banner.
	mux.Handle("/", s.dualAuth(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
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

// dualAuth accepts either a valid session cookie or HTTP basic auth.
// On failure it returns 401 with WWW-Authenticate so curl users get
// a prompt; UI users will already have a cookie.
func (s *Server) dualAuth(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Session cookie path.
		if sid := readSessionCookie(r); sid != "" {
			if _, _, ok := s.store.Get(sid); ok {
				next.ServeHTTP(w, r)
				return
			}
		}
		// Basic auth path.
		u, p, ok := r.BasicAuth()
		if ok &&
			subtle.ConstantTimeCompare([]byte(u), []byte(s.user)) == 1 &&
			subtle.ConstantTimeCompare([]byte(p), []byte(s.pass)) == 1 {
			next.ServeHTTP(w, r)
			return
		}
		w.Header().Set("WWW-Authenticate", `Basic realm="notrouter"`)
		http.Error(w, "unauthorized", http.StatusUnauthorized)
	})
}

// handleLegacyMux dispatches to the existing handler functions. Using a
// single-mux pattern keeps the dual-auth wrapper in one place.
func (s *Server) handleLegacyMux(w http.ResponseWriter, r *http.Request) {
	switch r.URL.Path {
	case "/admin/state":
		s.handleState(w, r)
	case "/admin/deliveries":
		s.handleDeliveries(w, r)
	case "/admin/dedup/clear":
		s.handleDedupClear(w, r)
	case "/admin/":
		s.handleAdminIndex(w, r)
	default:
		http.NotFound(w, r)
	}
}

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
		"status":          "degraded",
		"reasons":         degraded,
		"queues":          queues,
		"tracker_pending": pending,
		"dedup_size":      dedupSize,
	})
}

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
		"cleared":       true,
		"previous_size": before,
	})
}

func (s *Server) handleAdminIndex(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/plain")
	w.Write([]byte("notrouter admin\n\nendpoints:\n  GET  /admin/state\n  GET  /admin/deliveries\n  POST /admin/dedup/clear\n  UI:  /admin/ui/\n"))
}

func writeJSON(w http.ResponseWriter, status int, body interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(body)
}
