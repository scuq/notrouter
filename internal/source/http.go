package source

import (
	"context"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"net/http"
	"path"
	"strings"
	"time"

	"github.com/scuq/notrouter/internal/metrics"
)

type HTTP struct {
	addr          string
	name          string
	token         string
	tlsCert       string
	tlsKey        string
	allowedTopics []string
	metrics       *metrics.Metrics
	ch            chan Event
	srv           *http.Server
	doneCh        chan struct{}
}

type HTTPOption func(*HTTP)

func WithBearerToken(token string) HTTPOption {
	return func(h *HTTP) { h.token = token }
}

func WithMetrics(name string, m *metrics.Metrics) HTTPOption {
	return func(h *HTTP) {
		h.name = name
		h.metrics = m
	}
}

func WithTLS(cert, key string) HTTPOption {
	return func(h *HTTP) {
		h.tlsCert = cert
		h.tlsKey = key
	}
}

func WithAllowedTopics(patterns []string) HTTPOption {
	return func(h *HTTP) { h.allowedTopics = patterns }
}

func NewHTTP(addr string, opts ...HTTPOption) *HTTP {
	h := &HTTP{
		addr:   addr,
		ch:     make(chan Event, 64),
		doneCh: make(chan struct{}),
	}
	for _, opt := range opts {
		opt(h)
	}
	return h
}

func (h *HTTP) Start() error {
	mux := http.NewServeMux()
	mux.HandleFunc("/notify", h.auth(h.handleNotify))
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	h.srv = &http.Server{
		Addr:              h.addr,
		Handler:           mux,
		ReadHeaderTimeout: 5 * time.Second,
	}
	go func() {
		defer close(h.doneCh)
		var err error
		if h.tlsCert != "" {
			err = h.srv.ListenAndServeTLS(h.tlsCert, h.tlsKey)
		} else {
			err = h.srv.ListenAndServe()
		}
		if err != nil && !errors.Is(err, http.ErrServerClosed) {
			// shutdown signaled via Close
		}
	}()
	return nil
}

func (h *HTTP) auth(next http.HandlerFunc) http.HandlerFunc {
	if h.token == "" {
		return next
	}
	expected := []byte("Bearer " + h.token)
	return func(w http.ResponseWriter, r *http.Request) {
		got := r.Header.Get("Authorization")
		if subtle.ConstantTimeCompare([]byte(got), expected) != 1 &&
			subtle.ConstantTimeCompare([]byte(strings.TrimSpace(got)), expected) != 1 {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		next(w, r)
	}
}

const maxNotifyBody = 1 << 20 // 1 MiB

func (h *HTTP) handleNotify(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "POST required", http.StatusMethodNotAllowed)
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, maxNotifyBody)
	var ev Event
	if err := json.NewDecoder(r.Body).Decode(&ev); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	if ev.Topic == "" {
		http.Error(w, "topic required", http.StatusBadRequest)
		return
	}
	if !h.topicAllowed(ev.Topic) {
		http.Error(w, "topic not allowed for this source", http.StatusForbidden)
		return
	}
	if ev.Time.IsZero() {
		ev.Time = time.Now().UTC()
	}
	select {
	case h.ch <- ev:
		if h.metrics != nil {
			h.metrics.EventAccepted(h.name)
		}
		w.WriteHeader(http.StatusAccepted)
	default:
		if h.metrics != nil {
			h.metrics.EventDropped(h.name)
		}
		http.Error(w, "buffer full", http.StatusServiceUnavailable)
	}
}

func (h *HTTP) topicAllowed(topic string) bool {
	if len(h.allowedTopics) == 0 {
		return true
	}
	for _, pat := range h.allowedTopics {
		if pat == "*" || pat == topic {
			return true
		}
		if ok, err := path.Match(pat, topic); err == nil && ok {
			return true
		}
	}
	return false
}

func (h *HTTP) Events() <-chan Event { return h.ch }

func (h *HTTP) Close() error {
	if h.srv != nil {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = h.srv.Shutdown(ctx)
		<-h.doneCh
	}
	close(h.ch)
	return nil
}
