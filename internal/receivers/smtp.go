package receivers

import (
	"context"
	"fmt"
	"io"
	stdlog "log"
	"log/slog"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	smtplib "github.com/emersion/go-smtp"

	"github.com/scuq/notrouter/internal/config"
	"github.com/scuq/notrouter/internal/event"
	"github.com/scuq/notrouter/internal/metrics"
	"github.com/scuq/notrouter/internal/pipeline"
	"github.com/scuq/notrouter/internal/trace"
)

// SMTPReceiver implements an SMTP server that hands accepted messages off
// to the notrouter pipeline as events. Designed for monitoring traffic from
// systems that can only emit email notifications (Grafana, CheckMK, Palo
// Alto, vendor appliances, etc.).
//
// v0.3.0 scope: port 25 only, no auth, IP/RCPT/FROM allowlists for trust
// boundary. Each accepted email becomes a single RawEvent with attributes
// populated for from_address, to_address, subject, body, body_html,
// message_id, received_from_ip, size_bytes. Profiles use the existing
// from_field extractor to read these into structured attributes.
//
// What this is NOT:
//   - Not a mail relay - we accept and discard, never forward
//   - Not authenticated (port 587 + AUTH lands in v0.3.3)
//   - Not parser-aware (parser framework lands in v0.3.1)
//
// Concurrency: go-smtp spawns one goroutine per connection. Our Backend
// returns a fresh Session per connection. Sessions are NOT shared. Each
// Session.Data() call slurps the message, hands it to the rawCh channel
// (non-blocking via select+default for backpressure), and returns. The
// pipeline runs separately and consumes from rawCh.
type SMTPReceiver struct {
	cfg    config.SMTPPort25Config
	rawCh  chan<- *pipeline.RawEvent
	log    *slog.Logger
	server *smtplib.Server

	// Pre-compiled allowlist matchers. Built once at NewSMTPReceiver
	// time so per-connection checks are cheap.
	ipAllow   ipAllowlist
	rcptAllow rcptAllowlist
	fromAllow fromAllowlist

	// Stats. Exposed via /admin/state and Prometheus.
	accepted atomic.Uint64
	rejected atomic.Uint64

	// Optional tracer for debug capture. Set via SetTracer() after
	// construction. nil means trace disabled (zero overhead).
	tracer *trace.Tracer
}

// SetTracer wires in an optional trace.Tracer after construction. nil
// is fine and means trace is disabled for this receiver. Safe to call
// before Start() but not after - tracer is read on the hot path.
func (r *SMTPReceiver) SetTracer(t *trace.Tracer) {
	if r != nil {
		r.tracer = t
	}
}

// NewSMTPReceiver compiles the allowlists and prepares the server. Does
// NOT start listening - caller must call Start(). Returns nil if the
// config is disabled (lets callers skip wiring entirely).
func NewSMTPReceiver(cfg config.SMTPPort25Config, rawCh chan<- *pipeline.RawEvent, log *slog.Logger) (*SMTPReceiver, error) {
	if !cfg.Enabled {
		return nil, nil
	}

	// Empty allowlists default to deny-all for safety. The alternative
	// (empty = allow all) makes a typo in config catastrophically
	// permissive. Operators MUST explicitly say what's allowed.
	if len(cfg.AllowedIPs) == 0 {
		return nil, fmt.Errorf("smtp port_25 enabled but allowed_ips is empty (would deny all)")
	}
	if len(cfg.AllowedRcptTo) == 0 {
		return nil, fmt.Errorf("smtp port_25 enabled but allowed_rcpt_to is empty (would deny all)")
	}

	ipAllow, err := compileIPAllowlist(cfg.AllowedIPs)
	if err != nil {
		return nil, fmt.Errorf("smtp port_25 allowed_ips: %w", err)
	}
	rcptAllow := compileRcptAllowlist(cfg.AllowedRcptTo)
	fromAllow := compileFromAllowlist(cfg.AllowedFrom)

	maxBytes := int64(cfg.MaxMessageBytes)
	if maxBytes <= 0 {
		maxBytes = 1 << 20 // 1 MiB default
	}

	hostname := cfg.Hostname
	if hostname == "" {
		hostname = "notrouter.local"
	}

	r := &SMTPReceiver{
		cfg:       cfg,
		rawCh:     rawCh,
		log:       log,
		ipAllow:   ipAllow,
		rcptAllow: rcptAllow,
		fromAllow: fromAllow,
	}

	srv := smtplib.NewServer(&smtpBackend{recv: r})
	srv.Addr = cfg.Listen
	srv.Domain = hostname
	srv.MaxMessageBytes = maxBytes
	srv.MaxRecipients = 10
	srv.AllowInsecureAuth = true // we don't accept AUTH on port 25, this is moot
	srv.ReadTimeout = 30 * time.Second
	srv.WriteTimeout = 30 * time.Second

	// Discard go-smtp's own log output; we log at message boundaries
	// in our Backend implementation. go-smtp's internal logs are mostly
	// protocol noise (HELO/EHLO acks, etc.) and would clutter ours.
	srv.ErrorLog = stdlog.New(io.Discard, "", 0)

	r.server = srv
	return r, nil
}

func (r *SMTPReceiver) Name() string { return "smtp-25" }

func (r *SMTPReceiver) Start(ctx context.Context, wg *sync.WaitGroup) error {
	listener, err := net.Listen("tcp", r.cfg.Listen)
	if err != nil {
		return fmt.Errorf("smtp listen %s: %w", r.cfg.Listen, err)
	}

	wg.Add(1)
	go func() {
		defer wg.Done()
		r.log.Info("smtp-25 listening",
			"addr", r.cfg.Listen,
			"hostname", r.server.Domain,
			"max_message_bytes", r.server.MaxMessageBytes,
			"allowed_ip_entries", len(r.cfg.AllowedIPs),
			"allowed_rcpt_entries", len(r.cfg.AllowedRcptTo),
			"allowed_from_entries", len(r.cfg.AllowedFrom))

		// Server.Serve blocks until the listener is closed. The other
		// goroutine below handles ctx cancellation by closing the server.
		if err := r.server.Serve(listener); err != nil && !isClosedListener(err) {
			r.log.Error("smtp-25 serve", "err", err)
		}
	}()

	wg.Add(1)
	go func() {
		defer wg.Done()
		<-ctx.Done()
		// Close() shuts down the listener; in-flight sessions get a
		// reasonable amount of time to finish their current message.
		_ = r.server.Close()
	}()

	return nil
}

// SnapshotForState exposes counters to /admin/state. Same shape as the
// syslog filter's snapshot.
func (r *SMTPReceiver) SnapshotForState() map[string]interface{} {
	if r == nil {
		return map[string]interface{}{"enabled": false}
	}
	return map[string]interface{}{
		"enabled":  true,
		"listen":   r.cfg.Listen,
		"accepted": r.accepted.Load(),
		"rejected": r.rejected.Load(),
	}
}

// isClosedListener detects the "use of closed network connection" error
// from net.Listener.Accept after Close. Returned by the smtp server
// during graceful shutdown - not a real failure.
func isClosedListener(err error) bool {
	if err == nil {
		return false
	}
	return strings.Contains(err.Error(), "use of closed network connection")
}

// =====================================================================
// smtpBackend - implements go-smtp Backend interface
// =====================================================================

type smtpBackend struct {
	recv *SMTPReceiver
}

// NewSession is called once per TCP connection. We do the IP allowlist
// check here (cheapest possible spot) and reject before any SMTP commands
// are processed if the source IP isn't permitted.
func (b *smtpBackend) NewSession(c *smtplib.Conn) (smtplib.Session, error) {
	remoteIP := remoteIPFromConn(c.Conn().RemoteAddr())
	if !b.recv.ipAllow.allow(remoteIP) {
		b.recv.rejected.Add(1)
		b.recv.log.Warn("smtp-25 connection rejected",
			"reason", "ip_not_allowed",
			"remote_ip", remoteIP)
		return nil, &smtplib.SMTPError{
			Code:         554,
			EnhancedCode: smtplib.EnhancedCode{5, 7, 1},
			Message:      "access denied",
		}
	}
	return &smtpSession{
		recv:     b.recv,
		remoteIP: remoteIP,
	}, nil
}

// remoteIPFromConn extracts a string-form IP from a net.Addr. Returns
// "unknown" rather than crashing if the conn type is unexpected.
func remoteIPFromConn(addr net.Addr) string {
	if addr == nil {
		return "unknown"
	}
	if tcp, ok := addr.(*net.TCPAddr); ok {
		return tcp.IP.String()
	}
	host, _, err := net.SplitHostPort(addr.String())
	if err != nil {
		return addr.String()
	}
	return host
}

// =====================================================================
// smtpSession - per-connection state
// =====================================================================

type smtpSession struct {
	recv     *SMTPReceiver
	remoteIP string

	// Set by Mail/Rcpt before Data is called. Reset clears.
	from string
	to   []string
}

func (s *smtpSession) AuthPlain(username, password string) error {
	// Port 25 doesn't support AUTH. Returning an error here makes
	// AUTH negotiation fail cleanly.
	return smtplib.ErrAuthUnsupported
}

func (s *smtpSession) Mail(from string, opts *smtplib.MailOptions) error {
	from = strings.ToLower(strings.TrimSpace(from))
	if !s.recv.fromAllow.allow(from) {
		s.recv.rejected.Add(1)
		s.recv.log.Warn("smtp-25 MAIL FROM rejected",
			"reason", "from_not_allowed",
			"from", from,
			"remote_ip", s.remoteIP)
		return &smtplib.SMTPError{
			Code:         550,
			EnhancedCode: smtplib.EnhancedCode{5, 7, 1},
			Message:      "sender not allowed",
		}
	}
	s.from = from
	return nil
}

func (s *smtpSession) Rcpt(to string, opts *smtplib.RcptOptions) error {
	to = strings.ToLower(strings.TrimSpace(to))
	if !s.recv.rcptAllow.allow(to) {
		s.recv.rejected.Add(1)
		s.recv.log.Warn("smtp-25 RCPT TO rejected",
			"reason", "rcpt_not_allowed",
			"rcpt", to,
			"remote_ip", s.remoteIP)
		return &smtplib.SMTPError{
			Code:         550,
			EnhancedCode: smtplib.EnhancedCode{5, 7, 1},
			Message:      "recipient not allowed",
		}
	}
	s.to = append(s.to, to)
	return nil
}

func (s *smtpSession) Data(r io.Reader) error {
	// Read the full message body. go-smtp already enforces
	// MaxMessageBytes via its own LimitReader; we can ReadAll safely.
	body, err := io.ReadAll(r)
	if err != nil {
		s.recv.rejected.Add(1)
		s.recv.log.Warn("smtp-25 DATA read error",
			"err", err,
			"remote_ip", s.remoteIP)
		return &smtplib.SMTPError{
			Code:         554,
			EnhancedCode: smtplib.EnhancedCode{5, 0, 0},
			Message:      "data read error",
		}
	}

	// Trace capture - writes raw RFC 5322 bytes to disk if SMTP trace
	// is enabled. nil-safe (no-op when tracer is nil).
	s.recv.tracer.CaptureSMTP(s.from, body)

	parsed, err := parseEmail(body)
	if err != nil {
		// We accept the message even if parsing fails - some senders
		// emit non-standard headers and we'd rather see a malformed
		// event than silently drop. Log the parse error for tuning.
		s.recv.log.Warn("smtp-25 message parse warning",
			"err", err,
			"remote_ip", s.remoteIP,
			"size_bytes", len(body))
	}

	ev := event.New("smtp-25", body)
	ev.Attributes["from_address"] = s.from
	ev.Attributes["to_address"] = strings.Join(s.to, ",")
	ev.Attributes["subject"] = parsed.subject
	ev.Attributes["body"] = parsed.bodyText
	ev.Attributes["body_html"] = parsed.bodyHTML
	ev.Attributes["message_id"] = parsed.messageID
	ev.Attributes["received_from_ip"] = s.remoteIP
	ev.Attributes["size_bytes"] = fmtInt(len(body))

	// Set entity now so dedup/suppress/route layers can work even if
	// no profile sets it later. The profile is free to override.
	ev.Entity = s.from

	metrics.EventsReceived.WithLabelValues("smtp-25").Inc()
	s.recv.accepted.Add(1)

	s.recv.log.Info("smtp-25 message accepted",
		"from", s.from,
		"to", ev.Attributes["to_address"],
		"subject", parsed.subject,
		"size_bytes", len(body),
		"remote_ip", s.remoteIP)

	// Use the same profile name pattern as other receivers - "smtp"
	// matches the smtp_generic profile in the default config. Per-
	// vendor parsers in v0.3.1 will route based on RCPT TO.
	select {
	case s.recv.rawCh <- &pipeline.RawEvent{Profile: "smtp_generic", Event: ev}:
		return nil
	default:
		// Pipeline is congested. Return a temporary failure so the
		// sender retries after their queue cooldown. RFC 5321 4xx
		// codes are temporary; senders generally retry minutes-to-
		// hours later, which is fine for a transient backpressure
		// situation.
		s.recv.rejected.Add(1)
		s.recv.log.Warn("smtp-25 pipeline congested, rejecting message",
			"remote_ip", s.remoteIP)
		return &smtplib.SMTPError{
			Code:         451,
			EnhancedCode: smtplib.EnhancedCode{4, 4, 5},
			Message:      "pipeline congested, retry later",
		}
	}
}

func (s *smtpSession) Reset() {
	s.from = ""
	s.to = nil
}

func (s *smtpSession) Logout() error {
	return nil
}

// fmtInt formats an int as a string without pulling in strconv just for
// this. The body size is bounded by MaxMessageBytes (default 1 MiB =
// 1048576), so 7 digits at most.
func fmtInt(n int) string {
	if n == 0 {
		return "0"
	}
	negative := n < 0
	if negative {
		n = -n
	}
	var buf [20]byte
	i := len(buf)
	for n > 0 {
		i--
		buf[i] = byte('0' + n%10)
		n /= 10
	}
	if negative {
		i--
		buf[i] = '-'
	}
	return string(buf[i:])
}

// Compile-time assertion: smtpBackend satisfies go-smtp's Backend interface.
var _ smtplib.Backend = (*smtpBackend)(nil)
var _ smtplib.Session = (*smtpSession)(nil)
