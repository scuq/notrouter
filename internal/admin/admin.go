package admin

import (
	"context"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/prometheus/client_golang/prometheus/promhttp"

	"github.com/scuq/notrouter/internal/admin/creds"
	"github.com/scuq/notrouter/internal/logbuffer"
	"github.com/scuq/notrouter/internal/version"
)

const QueueDegradedRatio = 0.9

// authCtxKey is used to stash the authenticated username on the request
// context. Handlers downstream of auth() pull it out via authedUser(r).
type authCtxKey struct{}

// authedUser returns the username established by the auth middleware
// for this request. Empty string if not set (which means a handler is
// reachable without going through auth - bug).
func authedUser(r *http.Request) string {
	if v, ok := r.Context().Value(authCtxKey{}).(string); ok {
		return v
	}
	return ""
}

type Server struct {
	addr   string
	user   string
	creds  credsAccessor
	log    *slog.Logger
	server *http.Server
	store  *SessionStore
	uiH    *uiHandler

	rtMu sync.RWMutex
	rt   reloaderAccessor
}

func NewWithUI(
	addr string,
	basicUser string,
	creds credsAccessor,
	sessionTTL time.Duration,
	log *slog.Logger,
	rt reloaderAccessor,
	credsPath string,
	logs *logbuffer.Buffer,
) (*Server, error) {
	store := NewSessionStore(sessionTTL)
	uiH, err := newUIHandler(store, creds, sessionTTL, log, rt, credsPath, logs)
	if err != nil {
		return nil, err
	}
	return &Server{
		addr:  addr,
		user:  basicUser,
		creds: creds,
		log:   log,
		store: store,
		uiH:   uiH,
		rt:    rt,
	}, nil
}

func (s *Server) Start(ctx context.Context, wg *sync.WaitGroup) error {
	mux := http.NewServeMux()

	mux.HandleFunc("/healthz", s.handleHealthz)
	mux.Handle("/metrics", promhttp.Handler())
	mux.HandleFunc("/version", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, map[string]string{
			"version": version.Version,
			"commit":  version.Commit,
		})
	})

	s.uiH.register(mux)

	authed := s.auth(http.HandlerFunc(s.handleLegacyMux))
	mux.Handle("/admin/state", authed)
	mux.Handle("/admin/deliveries", authed)
	mux.Handle("/admin/dedup/clear", authed)
	mux.Handle("/admin/", authed)

	mux.Handle("/", s.auth(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
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

func (s *Server) currentProbes() Probes {
	s.rtMu.RLock()
	defer s.rtMu.RUnlock()
	return s.rt.Probes()
}

// auth is the unified auth middleware. Order of preference:
//  1. Session cookie (UI users; cheap, ~microseconds)
//  2. Bearer token (scripts; sha256+map lookup, ~microseconds)
//  3. HTTP basic auth (legacy curl; bcrypt verify, ~10ms)
//
// On success, the username is attached to the request context so
// handlers can record who did what.
func (s *Server) auth(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// 1) Session cookie
		if sid := readSessionCookie(r); sid != "" {
			if user, _, ok := s.store.Get(sid); ok {
				next.ServeHTTP(w, r.WithContext(withUser(r.Context(), user)))
				return
			}
		}

		// 2) Bearer token
		if user, ok := s.tryBearer(r); ok {
			next.ServeHTTP(w, r.WithContext(withUser(r.Context(), user)))
			return
		}

		// 3) Basic auth
		u, p, ok := r.BasicAuth()
		if ok &&
			subtle.ConstantTimeCompare([]byte(u), []byte(s.user)) == 1 &&
			s.creds.Verify(p) {
			next.ServeHTTP(w, r.WithContext(withUser(r.Context(), u)))
			return
		}

		w.Header().Set("WWW-Authenticate", `Basic realm="notrouter"`)
		http.Error(w, "unauthorized", http.StatusUnauthorized)
	})
}

func withUser(ctx context.Context, user string) context.Context {
	return context.WithValue(ctx, authCtxKey{}, user)
}

// tryBearer pulls "Authorization: Bearer <token>" out of the request
// and asks the creds store to verify. Returns the owning username on
// success. Distinguishes "no header" (return false silently) from
// "bad token" (also false but logged for ops visibility).
func (s *Server) tryBearer(r *http.Request) (string, bool) {
	hdr := r.Header.Get("Authorization")
	if hdr == "" || !strings.HasPrefix(hdr, "Bearer ") {
		return "", false
	}
	token := strings.TrimPrefix(hdr, "Bearer ")
	user, err := s.creds.VerifyToken(token)
	if err != nil {
		// Quiet on bad-token; tokens turn over and we don't want to
		// flood logs with failed scripts. Operator can grep for this
		// at debug level.
		switch {
		case errors.Is(err, creds.ErrTokenExpired):
			s.log.Debug("bearer token expired", "remote", r.RemoteAddr)
		case errors.Is(err, creds.ErrTokenNotFound):
			s.log.Debug("bearer token not found", "remote", r.RemoteAddr)
		case errors.Is(err, creds.ErrInvalidToken):
			s.log.Debug("bearer token malformed", "remote", r.RemoteAddr)
		default:
			s.log.Warn("bearer verify error", "err", err)
		}
		return "", false
	}
	return user, true
}

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

	probes := s.currentProbes()

	if probes.Dispatch != nil {
		for _, q := range probes.Dispatch.QueueState() {
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
	if probes.Tracker != nil {
		pending = probes.Tracker.Pending()
		if pending > 10000 {
			degraded = append(degraded, "tracker_pending_high")
		}
	}

	dedupSize := 0
	if probes.Dedup != nil {
		dedupSize = probes.Dedup.Size()
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
	probes := s.currentProbes()
	state := map[string]interface{}{
		"version": map[string]string{
			"version": version.Version,
			"commit":  version.Commit,
		},
	}
	if probes.Dispatch != nil {
		state["queues"] = probes.Dispatch.QueueState()
	}
	if probes.Dedup != nil {
		state["dedup_size"] = probes.Dedup.Size()
	}
	if probes.Tracker != nil {
		state["tracker_pending"] = probes.Tracker.Pending()
	}
	writeJSON(w, http.StatusOK, state)
}

func (s *Server) handleDeliveries(w http.ResponseWriter, r *http.Request) {
	probes := s.currentProbes()
	if probes.Tracker == nil {
		writeJSON(w, http.StatusOK, map[string]interface{}{"recent": []interface{}{}})
		return
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"pending": probes.Tracker.Pending(),
		"recent":  probes.Tracker.RecentFinal(),
	})
}

func (s *Server) handleDedupClear(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "POST required", http.StatusMethodNotAllowed)
		return
	}
	probes := s.currentProbes()
	if probes.Dedup == nil {
		http.Error(w, "dedup not available", http.StatusServiceUnavailable)
		return
	}
	before := probes.Dedup.Size()
	probes.Dedup.Clear()
	s.log.Warn("dedup cleared via admin endpoint",
		"previous_size", before,
		"user", authedUser(r))
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
