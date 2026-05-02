package sink

import (
	"fmt"
	"log/slog"
	"os"

	"github.com/scuq/notrouter/internal/config"
	"github.com/scuq/notrouter/internal/metrics"
)

func BuildWorkers(cfgs []config.SinkConfig, log *slog.Logger, m *metrics.Metrics) ([]*Worker, map[string]*Worker, error) {
	workers := make([]*Worker, 0, len(cfgs))
	byName := make(map[string]*Worker, len(cfgs))
	for _, c := range cfgs {
		s, err := buildOne(c)
		if err != nil {
			return nil, nil, fmt.Errorf("sink %q: %w", c.Name, err)
		}
		if _, dup := byName[c.Name]; dup {
			return nil, nil, fmt.Errorf("duplicate sink name %q", c.Name)
		}
		w := NewWorker(c.Name, s, c.QueueSize, log, m)
		w.Start()
		workers = append(workers, w)
		byName[c.Name] = w
	}
	return workers, byName, nil
}

func buildOne(c config.SinkConfig) (Sink, error) {
	switch c.Type {
	case "stdout":
		return NewStdout(os.Stdout), nil
	case "file":
		if c.Path == "" {
			return nil, fmt.Errorf("file sink requires path")
		}
		return NewFile(c.Path), nil
	case "smtp":
		smtpOpts := []SMTPOption{}
		if c.SMTPUser != "" {
			smtpOpts = append(smtpOpts, SMTPWithAuth(c.SMTPUser, c.SMTPPass))
		}
		if c.Subject != "" {
			smtpOpts = append(smtpOpts, SMTPWithSubjectTemplate(c.Subject))
		}
		if c.Body != "" {
			smtpOpts = append(smtpOpts, SMTPWithBodyTemplate(c.Body))
		}
		return NewSMTP(c.SMTPHost, c.SMTPPort, c.From, c.To, smtpOpts...)
	case "webhook":
		if c.URL == "" {
			return nil, fmt.Errorf("webhook sink requires url")
		}
		opts := []WebhookOption{}
		if c.MaxRetries > 0 {
			opts = append(opts, WithMaxRetries(c.MaxRetries))
		}
		if c.AuthToken != "" {
			opts = append(opts, WithAuthToken(c.AuthToken))
		}
		if c.HMACSecret != "" {
			opts = append(opts, WithHMAC(c.HMACSecret, c.HMACHeader))
		}
		if c.Template != "" {
			opts = append(opts, WithTemplate(c.Template))
		}
		if c.ContentType != "" {
			opts = append(opts, WithContentType(c.ContentType))
		}
		return NewWebhook(c.URL, opts...)
	default:
		return nil, fmt.Errorf("unknown sink type %q", c.Type)
	}
}
