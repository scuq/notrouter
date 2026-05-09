package receivers

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/scuq/notrouter/internal/admin/creds"
	"github.com/scuq/notrouter/internal/config"
	"github.com/scuq/notrouter/internal/event"
	"github.com/scuq/notrouter/internal/metrics"
	"github.com/scuq/notrouter/internal/pipeline"
	"github.com/scuq/notrouter/internal/trace"
)

// WebhookKeyVerifier is the surface the receiver needs from the creds
// store. Defined as an interface so we don't drag the full *creds.Store
// into the receivers package's import graph; main.go passes the store
// in and Go's structural typing makes it Just Work.
type WebhookKeyVerifier interface {
	VerifyWebhookKey(plain string) error
	HasAnyWebhookKey() bool
}

type WebhookReceiver struct {
	addr        string
	endpoints   []config.WebhookEndpoint
	rawCh       chan<- *pipeline.RawEvent
	log         *slog.Logger
	server      *http.Server
	verifier    WebhookKeyVerifier
	requireAuth bool // forces auth even when no keys exist

	tracer  *trace.Tracer
}

// SetTracer wires in an optional trace.Tracer. nil-safe.
func (w *WebhookReceiver) SetTracer(t *trace.Tracer) {
	if w != nil {
		w.tracer = t
	}
}

// NewWebhook is the legacy constructor (no auth). Kept for backwards
// compatibility with anything that hasn't been updated to NewWebhookWithAuth.
func NewWebhook(addr string, endpoints []config.WebhookEndpoint, rawCh chan<- *pipeline.RawEvent, log *slog.Logger) *WebhookReceiver {
	return &WebhookReceiver{addr: addr, endpoints: endpoints, rawCh: rawCh, log: log}
}

// NewWebhookWithAuth wires in the creds verifier and the require-auth flag.
// Auth enforcement rule:
//   - requireAuth=true: every POST must present a valid key, even if no
//     keys are minted (which would lock everything out - useful for paranoid
//     deployments that want zero ambiguity).
//   - requireAuth=false (default): if no keys exist, no auth needed (legacy
//     behavior). Once at least one key exists, all POSTs must authenticate.
func NewWebhookWithAuth(
	addr string,
	endpoints []config.WebhookEndpoint,
	rawCh chan<- *pipeline.RawEvent,
	log *slog.Logger,
	verifier WebhookKeyVerifier,
	requireAuth bool,
) *WebhookReceiver {
	return &WebhookReceiver{
		addr:        addr,
		endpoints:   endpoints,
		rawCh:       rawCh,
		log:         log,
		verifier:    verifier,
		requireAuth: requireAuth,
	}
}

func (w *WebhookReceiver) Name() string { return "webhook" }

// authCheck returns nil if the request is authorized, or an error
// describing why not. If no verifier is configured (NewWebhook constructor
// was used), auth is skipped entirely - that's the no-changes-required
// path for tests and pre-v0.2.3 callers.
func (w *WebhookReceiver) authCheck(r *http.Request) error {
	if w.verifier == nil {
		return nil
	}
	if !w.requireAuth && !w.verifier.HasAnyWebhookKey() {
		// Backwards-compatibility mode: zero keys minted means anyone can
		// POST. Operator turns enforcement on by minting their first key.
		return nil
	}
	hdr := r.Header.Get("Authorization")
	if !strings.HasPrefix(hdr, "Bearer ") {
		return errors.New("missing bearer token")
	}
	key := strings.TrimPrefix(hdr, "Bearer ")
	if !strings.HasPrefix(key, creds.WebhookKeyPrefix) {
		// This catches the most likely operator mistake: using an API
		// token (notr_<hex>) as a webhook key. Cleaner error than just
		// "invalid".
		return errors.New("token is not a webhook key (missing wh_ prefix)")
	}
	return w.verifier.VerifyWebhookKey(key)
}

func (w *WebhookReceiver) Start(ctx context.Context, wg *sync.WaitGroup) error {
	mux := http.NewServeMux()

	for _, ep := range w.endpoints {
		ep := ep
		mux.HandleFunc(ep.Path, func(rw http.ResponseWriter, r *http.Request) {
			if err := w.authCheck(r); err != nil {
				// Log at INFO not WARN - failed auth is expected day-to-day
				// noise (port scanners, misconfigured clients). Bumping to
				// WARN would drown the log with non-actionable lines.
				w.log.Info("webhook auth rejected",
					"path", r.URL.Path,
					"remote", r.RemoteAddr,
					"reason", err.Error())
				rw.Header().Set("WWW-Authenticate", `Bearer realm="notrouter-webhook"`)
				http.Error(rw, "unauthorized: "+err.Error(), http.StatusUnauthorized)
				return
			}

			body, err := io.ReadAll(io.LimitReader(r.Body, 1<<20))
			if err != nil {
				http.Error(rw, "read error", http.StatusBadRequest)
				return
			}
			// Trace capture. Reads happen-once - we already have body in memory.
			// nil-safe (no-op when tracer is nil).
			srcIPForTrace := r.RemoteAddr
			if h, _, splitErr := net.SplitHostPort(r.RemoteAddr); splitErr == nil {
				srcIPForTrace = h
			}
			w.tracer.CaptureWebhook(r.Method, r.URL.Path, srcIPForTrace, r.Header, body)

			defer r.Body.Close()

			ev := event.New("webhook:"+ep.Profile, body)
			ev.Attributes["http_method"] = r.Method
			ev.Attributes["http_path"] = r.URL.Path
			ev.Attributes["http_remote"] = r.RemoteAddr
			// origin_id - stable across-receiver identifier for the sender.
			// Uses IP only (no port); port varies per request but IP doesn't.
			originID := r.RemoteAddr
			if h, _, splitErr := net.SplitHostPort(r.RemoteAddr); splitErr == nil {
				originID = h
			}
			ev.Attributes["origin_id"] = originID

			metrics.EventsReceived.WithLabelValues("webhook:" + ep.Profile).Inc()

			select {
			case w.rawCh <- &pipeline.RawEvent{Profile: ep.Profile, Event: ev}:
				rw.WriteHeader(http.StatusAccepted)
			case <-r.Context().Done():
				http.Error(rw, "request cancelled", http.StatusServiceUnavailable)
			default:
				http.Error(rw, "queue full", http.StatusServiceUnavailable)
			}
		})
	}

	w.server = &http.Server{
		Addr:              w.addr,
		Handler:           mux,
		ReadHeaderTimeout: 5 * time.Second,
	}

	wg.Add(1)
	go func() {
		defer wg.Done()
		// Log whether auth is enforced so operators can grep startup
		// to confirm what mode the receiver is in.
		mode := "open"
		if w.verifier != nil {
			if w.requireAuth {
				mode = "auth-required (config flag)"
			} else if w.verifier.HasAnyWebhookKey() {
				mode = "auth-required (keys present)"
			} else {
				mode = "open (no keys minted)"
			}
		}
		w.log.Info("webhook listening", "addr", w.addr, "auth", mode)
		if err := w.server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			w.log.Error("webhook server error", "err", err)
		}
	}()

	wg.Add(1)
	go func() {
		defer wg.Done()
		<-ctx.Done()
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = w.server.Shutdown(shutdownCtx)
	}()

	return nil
}
