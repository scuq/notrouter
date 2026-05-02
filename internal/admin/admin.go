package admin

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"sort"
	"time"

	"github.com/scuq/notrouter/internal/metrics"
	"github.com/scuq/notrouter/internal/silence"
)

// QueueProbe describes one entity whose queue depth we report at /healthz.
type QueueProbe struct {
	Name  string
	Depth func() (int, int) // returns (len, cap)
}

const queueWarnRatio = 0.9

type Server struct {
	addr     string
	metrics  *metrics.Metrics
	silences *silence.Store
	probes   []QueueProbe
	srv      *http.Server
	doneCh   chan struct{}
}

func New(addr string, m *metrics.Metrics, s *silence.Store, probes ...QueueProbe) *Server {
	return &Server{
		addr:     addr,
		metrics:  m,
		silences: s,
		probes:   probes,
		doneCh:   make(chan struct{}),
	}
}

func (s *Server) Start() error {
	mux := http.NewServeMux()
	mux.HandleFunc("/metrics", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/plain; version=0.0.4")
		_ = s.metrics.WriteText(w)
	})
	mux.HandleFunc("/healthz", s.handleHealthz)
	if s.silences != nil {
		mux.HandleFunc("/silences", s.handleSilences)
	}
	s.srv = &http.Server{
		Addr:              s.addr,
		Handler:           mux,
		ReadHeaderTimeout: 5 * time.Second,
	}
	go func() {
		defer close(s.doneCh)
		if err := s.srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			// shutdown signaled via Close
		}
	}()
	return nil
}

type queueStatus struct {
	Name string `json:"name"`
	Len  int    `json:"len"`
	Cap  int    `json:"cap"`
}

type healthResponse struct {
	Status string        `json:"status"`
	Queues []queueStatus `json:"queues"`
}

func (s *Server) handleHealthz(w http.ResponseWriter, _ *http.Request) {
	resp := healthResponse{Status: "ok", Queues: make([]queueStatus, 0, len(s.probes))}
	hot := false
	for _, p := range s.probes {
		l, c := p.Depth()
		resp.Queues = append(resp.Queues, queueStatus{Name: p.Name, Len: l, Cap: c})
		if c > 0 && float64(l)/float64(c) >= queueWarnRatio {
			hot = true
		}
	}
	if hot {
		resp.Status = "degraded"
	}
	w.Header().Set("Content-Type", "application/json")
	if hot {
		w.WriteHeader(http.StatusServiceUnavailable)
	}
	_ = json.NewEncoder(w).Encode(resp)
}

type silenceRequest struct {
	Topic    string `json:"topic"`
	Duration string `json:"duration"`
}

func (s *Server) handleSilences(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		list := s.silences.List()
		sort.Slice(list, func(i, j int) bool { return list[i].Expires.Before(list[j].Expires) })
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(list)
	case http.MethodPost:
		var req silenceRequest
		if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<14)).Decode(&req); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		ttl, err := time.ParseDuration(req.Duration)
		if err != nil {
			http.Error(w, "invalid duration: "+err.Error(), http.StatusBadRequest)
			return
		}
		sil, err := s.silences.Add(req.Topic, ttl)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		_ = json.NewEncoder(w).Encode(sil)
	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

func (s *Server) Close() error {
	if s.srv == nil {
		return nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	err := s.srv.Shutdown(ctx)
	<-s.doneCh
	return err
}
