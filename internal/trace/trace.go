package trace

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/scuq/notrouter/internal/config"
)

// Tracer captures raw incoming data from receivers to disk for debugging.
// One Tracer instance handles all receiver types via per-receiver writers
// (different file shapes/rotation policies).
//
// Trace is a DEBUG-ONLY feature. Default disabled. Performance impact when
// enabled is acceptable (synchronous writes, full data captured) - the
// expectation is operators enable trace, reproduce a problem, look at
// files, and disable. Not for long-running production capture.
//
// Security: trace files contain raw data including potentially sensitive
// content (auth headers in webhook traces, alert details in SMTP, deny-log
// IPs in syslog). Files are written with 0600 perms, directory with 0700.
// Operators are reminded periodically that trace is on.
//
// Failure mode: write errors NEVER block the receiver. We log a warning
// once per error type, increment a drop counter, and continue. Losing
// trace data on disk-full is acceptable; losing real events is not.
type Tracer struct {
	cfg config.TraceConfig
	log *slog.Logger

	smtp      *perMessageWriter // SMTP: one .eml file per message
	syslogUDP *appendWriter     // syslog UDP: append-mode JSONL
	syslogTCP *appendWriter     // syslog TCP: append-mode JSONL
	webhook   *appendWriter     // webhook: append-mode JSONL
	tcpJSON   *appendWriter     // tcp_json: append-mode JSONL

	// Track when we last logged a write error per receiver type, so we
	// don't spam the log on persistent failures (disk full, perm denied).
	errLogCool   sync.Map // map[string]time.Time
	errLogPeriod time.Duration

	// Flag for the periodic-reminder goroutine to stop.
	stopReminder chan struct{}
	wg           sync.WaitGroup
}

// New creates a Tracer from config. Returns nil if trace is globally
// disabled (callers can check `tracer == nil` to skip work entirely).
//
// Validates the output directory exists or can be created with 0700 perms.
// If validation fails, returns an error - we'd rather refuse to start than
// silently drop trace data. The pipeline will run normally without trace.
func New(cfg config.TraceConfig, log *slog.Logger) (*Tracer, error) {
	if !cfg.Enabled {
		return nil, nil
	}

	outDir := cfg.OutputDir
	if outDir == "" {
		outDir = "/var/log/notrouter/trace"
	}

	if err := os.MkdirAll(outDir, 0700); err != nil {
		return nil, fmt.Errorf("trace output_dir: %w", err)
	}
	// Verify writability with a probe file - cheap test.
	probe := filepath.Join(outDir, ".write-probe")
	if err := os.WriteFile(probe, []byte("probe"), 0600); err != nil {
		return nil, fmt.Errorf("trace output_dir not writable: %w", err)
	}
	_ = os.Remove(probe)

	t := &Tracer{
		cfg:          cfg,
		log:          log,
		errLogPeriod: 60 * time.Second,
		stopReminder: make(chan struct{}),
	}

	if cfg.Receivers.SMTP.Enabled {
		t.smtp = newPerMessageWriter(filepath.Join(outDir, "smtp"), cfg.Receivers.SMTP.MaxFiles, log)
	}
	if cfg.Receivers.SyslogUDP.Enabled {
		w, err := newAppendWriter(filepath.Join(outDir, "syslog_udp"),
			"syslog_udp",
			cfg.Receivers.SyslogUDP.MaxBytesPerFile,
			cfg.Receivers.SyslogUDP.MaxFiles,
			log)
		if err != nil {
			return nil, fmt.Errorf("trace syslog_udp: %w", err)
		}
		t.syslogUDP = w
	}
	if cfg.Receivers.SyslogTCP.Enabled {
		w, err := newAppendWriter(filepath.Join(outDir, "syslog_tcp"),
			"syslog_tcp",
			cfg.Receivers.SyslogTCP.MaxBytesPerFile,
			cfg.Receivers.SyslogTCP.MaxFiles,
			log)
		if err != nil {
			return nil, fmt.Errorf("trace syslog_tcp: %w", err)
		}
		t.syslogTCP = w
	}
	if cfg.Receivers.Webhook.Enabled {
		w, err := newAppendWriter(filepath.Join(outDir, "webhook"),
			"webhook",
			cfg.Receivers.Webhook.MaxBytesPerFile,
			cfg.Receivers.Webhook.MaxFiles,
			log)
		if err != nil {
			return nil, fmt.Errorf("trace webhook: %w", err)
		}
		t.webhook = w
	}
	if cfg.Receivers.TCPJSON.Enabled {
		w, err := newAppendWriter(filepath.Join(outDir, "tcp_json"),
			"tcp_json",
			cfg.Receivers.TCPJSON.MaxBytesPerFile,
			cfg.Receivers.TCPJSON.MaxFiles,
			log)
		if err != nil {
			return nil, fmt.Errorf("trace tcp_json: %w", err)
		}
		t.tcpJSON = w
	}

	t.logEnabledReceivers()
	t.startPeriodicReminder()
	return t, nil
}

func (t *Tracer) logEnabledReceivers() {
	enabled := []string{}
	if t.smtp != nil {
		enabled = append(enabled, "smtp")
	}
	if t.syslogUDP != nil {
		enabled = append(enabled, "syslog_udp")
	}
	if t.syslogTCP != nil {
		enabled = append(enabled, "syslog_tcp")
	}
	if t.webhook != nil {
		enabled = append(enabled, "webhook")
	}
	if t.tcpJSON != nil {
		enabled = append(enabled, "tcp_json")
	}
	if len(enabled) == 0 {
		t.log.Warn("trace is globally enabled but no per-receiver toggles are on - no data will be captured")
		return
	}
	t.log.Warn("TRACE IS ENABLED - debug feature should not be left on in production",
		"receivers", enabled,
		"output_dir", t.cfg.OutputDir)
}

// startPeriodicReminder logs every cfg.ReminderInterval that trace is on.
// Default 1h. Operators sometimes flip trace on, get distracted, forget.
// The reminder is intentionally noisy.
func (t *Tracer) startPeriodicReminder() {
	interval := t.cfg.ReminderInterval
	if interval <= 0 {
		interval = 1 * time.Hour
	}

	t.wg.Add(1)
	go func() {
		defer t.wg.Done()
		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		for {
			select {
			case <-ticker.C:
				t.log.Warn("REMINDER: trace is still enabled - disable when debugging is complete",
					"output_dir", t.cfg.OutputDir)
			case <-t.stopReminder:
				return
			}
		}
	}()
}

// Stop closes all writers and stops the reminder goroutine. Safe to call
// when t is nil (Tracer disabled).
func (t *Tracer) Stop() {
	if t == nil {
		return
	}
	close(t.stopReminder)
	t.wg.Wait()
	if t.smtp != nil {
		t.smtp.close()
	}
	if t.syslogUDP != nil {
		_ = t.syslogUDP.close()
	}
	if t.syslogTCP != nil {
		_ = t.syslogTCP.close()
	}
	if t.webhook != nil {
		_ = t.webhook.close()
	}
	if t.tcpJSON != nil {
		_ = t.tcpJSON.close()
	}
}

// =====================================================================
// Capture methods - one per receiver type.
//
// All methods are safe to call when t is nil OR when the specific
// receiver isn't enabled. Receivers should call these unconditionally
// without nil checks.
// =====================================================================

// CaptureSMTP writes one .eml file per accepted message. The body should
// be the full RFC 5322 message bytes including headers. fromAddr is used
// only for the filename (sanitized for filesystem safety).
func (t *Tracer) CaptureSMTP(fromAddr string, body []byte) {
	if t == nil || t.smtp == nil {
		return
	}
	if err := t.smtp.write(fromAddr, body); err != nil {
		t.maybeLogErr("smtp", err)
	}
}

// CaptureSyslogUDP writes one JSONL line per datagram with timestamp,
// source IP, and raw bytes (base64-encoded for safety - syslog can
// contain non-printable chars and embedded newlines).
func (t *Tracer) CaptureSyslogUDP(srcIP string, body []byte) {
	if t == nil || t.syslogUDP == nil {
		return
	}
	if err := t.syslogUDP.writeJSONL(syslogRecord(srcIP, body)); err != nil {
		t.maybeLogErr("syslog_udp", err)
	}
}

// CaptureSyslogTCP same shape as CaptureSyslogUDP.
func (t *Tracer) CaptureSyslogTCP(srcIP string, body []byte) {
	if t == nil || t.syslogTCP == nil {
		return
	}
	if err := t.syslogTCP.writeJSONL(syslogRecord(srcIP, body)); err != nil {
		t.maybeLogErr("syslog_tcp", err)
	}
}

// CaptureWebhook writes one JSONL line per HTTP request with full headers
// (including Authorization! - operators MUST treat trace files as secrets)
// and body.
func (t *Tracer) CaptureWebhook(method, path, srcIP string, headers map[string][]string, body []byte) {
	if t == nil || t.webhook == nil {
		return
	}
	if err := t.webhook.writeJSONL(webhookRecord(method, path, srcIP, headers, body)); err != nil {
		t.maybeLogErr("webhook", err)
	}
}

// CaptureTCPJSON writes one JSONL trace entry per incoming TCP-JSON
// line. srcIP is the connection's peer IP. body is the raw JSON-line
// bytes (without the trailing newline).
func (t *Tracer) CaptureTCPJSON(srcIP string, body []byte) {
	if t == nil || t.tcpJSON == nil {
		return
	}
	if err := t.tcpJSON.writeJSONL(syslogRecord(srcIP, body)); err != nil {
		t.maybeLogErr("tcp_json", err)
	}
}

// maybeLogErr emits a warning at most once per t.errLogPeriod per
// receiver type, so disk-full doesn't spam the log thousands of times.
func (t *Tracer) maybeLogErr(receiverType string, err error) {
	now := time.Now()
	if last, ok := t.errLogCool.Load(receiverType); ok {
		if now.Sub(last.(time.Time)) < t.errLogPeriod {
			return
		}
	}
	t.errLogCool.Store(receiverType, now)
	t.log.Warn("trace write failed",
		"receiver", receiverType,
		"err", err,
		"note", "further failures suppressed for "+t.errLogPeriod.String())
}

// =====================================================================
// Record builders - JSONL line shapes
// =====================================================================

type syslogJSONRec struct {
	TS    string `json:"ts"`
	SrcIP string `json:"src_ip"`
	Raw   string `json:"raw"` // hex-printable raw bytes; non-ASCII shown as \xNN
}

func syslogRecord(srcIP string, body []byte) []byte {
	rec := syslogJSONRec{
		TS:    time.Now().UTC().Format(time.RFC3339Nano),
		SrcIP: srcIP,
		Raw:   safeRawString(body),
	}
	out, _ := json.Marshal(rec)
	out = append(out, '\n')
	return out
}

type webhookJSONRec struct {
	TS      string              `json:"ts"`
	Method  string              `json:"method"`
	Path    string              `json:"path"`
	SrcIP   string              `json:"src_ip"`
	Headers map[string][]string `json:"headers"`
	Body    string              `json:"body"`
}

func webhookRecord(method, path, srcIP string, headers map[string][]string, body []byte) []byte {
	rec := webhookJSONRec{
		TS:      time.Now().UTC().Format(time.RFC3339Nano),
		Method:  method,
		Path:    path,
		SrcIP:   srcIP,
		Headers: headers,
		Body:    string(body), // webhook bodies are typically JSON; safe to embed as string
	}
	out, _ := json.Marshal(rec)
	out = append(out, '\n')
	return out
}

// safeRawString renders bytes so the resulting string is JSON-safe AND
// readable in `tail` output. Printable ASCII passes through; everything
// else becomes \xNN. Avoids base64 (operators want grep'able output).
func safeRawString(b []byte) string {
	out := make([]byte, 0, len(b))
	for _, c := range b {
		switch {
		case c == '\\':
			out = append(out, '\\', '\\')
		case c == '\n':
			out = append(out, '\\', 'n')
		case c == '\r':
			out = append(out, '\\', 'r')
		case c == '\t':
			out = append(out, '\\', 't')
		case c >= 0x20 && c < 0x7f:
			out = append(out, c)
		default:
			out = append(out, '\\', 'x',
				hexNibble(c>>4), hexNibble(c&0x0f))
		}
	}
	return string(out)
}

func hexNibble(n byte) byte {
	if n < 10 {
		return '0' + n
	}
	return 'a' + (n - 10)
}
