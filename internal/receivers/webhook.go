package receivers

import (
	"context"
	"io"
	"log/slog"
	"net/http"
	"sync"
	"time"

	"github.com/scuq/notrouter/internal/config"
	"github.com/scuq/notrouter/internal/event"
	"github.com/scuq/notrouter/internal/metrics"
	"github.com/scuq/notrouter/internal/pipeline"
)

type WebhookReceiver struct {
	addr      string
	endpoints []config.WebhookEndpoint
	rawCh     chan<- *pipeline.RawEvent
	log       *slog.Logger
	server    *http.Server
}

func NewWebhook(addr string, endpoints []config.WebhookEndpoint, rawCh chan<- *pipeline.RawEvent, log *slog.Logger) *WebhookReceiver {
	return &WebhookReceiver{addr: addr, endpoints: endpoints, rawCh: rawCh, log: log}
}

func (w *WebhookReceiver) Name() string { return "webhook" }

func (w *WebhookReceiver) Start(ctx context.Context, wg *sync.WaitGroup) error {
	mux := http.NewServeMux()

	for _, ep := range w.endpoints {
		ep := ep
		mux.HandleFunc(ep.Path, func(rw http.ResponseWriter, r *http.Request) {
			body, err := io.ReadAll(io.LimitReader(r.Body, 1<<20))
			if err != nil {
				http.Error(rw, "read error", http.StatusBadRequest)
				return
			}
			defer r.Body.Close()

			ev := event.New("webhook:"+ep.Profile, body)
			ev.Attributes["http_method"] = r.Method
			ev.Attributes["http_path"] = r.URL.Path
			ev.Attributes["http_remote"] = r.RemoteAddr

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
		w.log.Info("webhook listening", "addr", w.addr)
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
