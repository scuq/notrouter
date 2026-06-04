package receivers

import (
	"bufio"
	"context"
	"errors"
	"io"
	"log/slog"
	"net"
	"sync"
	"time"

	"github.com/scuq/notrouter/internal/config"
	"github.com/scuq/notrouter/internal/event"
	"github.com/scuq/notrouter/internal/metrics"
	"github.com/scuq/notrouter/internal/pipeline"
	"github.com/scuq/notrouter/internal/trace"
)

// TCPJSONReceiver accepts newline-delimited JSON messages over TCP.
//
// Designed to replace Logstash as a protocol bridge for the
// community.general.logstash Ansible callback (and other newline-
// JSON-over-TCP shippers). Each line is one event; the pipeline
// handles it identically to a webhook event - same profile resolution,
// same dedup, same routing.
//
// Connection lifecycle:
//   - sender opens TCP socket, may stay open for the lifetime of the
//     application (Ansible: lifetime of one playbook run)
//   - sender writes JSON-objects, each terminated by \n
//   - many messages per connection; many connections may be open at
//     once (parallel playbook runs)
//
// origin_id is set to the immediate connection peer's IP - the JSON
// body's "host" field is NOT used as origin_id even when present,
// because that field is sender-controlled and would let any source
// claim any identity. Operators alias by the peer IP via
// source_aliases.
type TCPJSONReceiver struct {
	cfg      config.TCPJSONPort5044Config
	rawCh    chan<- *pipeline.RawEvent
	log      *slog.Logger
	listener net.Listener
	tracer   *trace.Tracer

	// Compiled CIDR allowlist. nil if AllowedIPs is empty
	// (then all connections are rejected - secure default).
	allowedNets []*net.IPNet

	// Max bytes per single JSON line. Defaults to 1 MiB if
	// MaxMessageBytes is zero.
	maxLine int
}

// NewTCPJSON constructs a receiver. Returns an error if the config is
// invalid (bad CIDR, etc) so the runtime can fail-fast at startup.
func NewTCPJSON(cfg config.TCPJSONPort5044Config, rawCh chan<- *pipeline.RawEvent, log *slog.Logger) (*TCPJSONReceiver, error) {
	r := &TCPJSONReceiver{
		cfg:     cfg,
		rawCh:   rawCh,
		log:     log,
		maxLine: cfg.MaxMessageBytes,
	}
	if r.maxLine <= 0 {
		r.maxLine = 1 << 20 // 1 MiB
	}

	// Compile allowed_ips. An empty list is treated as "deny all" -
	// senders MUST be explicitly allowlisted. This matches the SMTP
	// receiver's safety stance.
	for _, c := range cfg.AllowedIPs {
		if _, n, err := net.ParseCIDR(c); err == nil {
			r.allowedNets = append(r.allowedNets, n)
		} else {
			return nil, errors.New("tcp_json: invalid allowed_ips CIDR: " + c + ": " + err.Error())
		}
	}
	return r, nil
}

// SetTracer wires in an optional trace.Tracer. nil-safe.
func (s *TCPJSONReceiver) SetTracer(t *trace.Tracer) {
	if s != nil {
		s.tracer = t
	}
}

// Start binds the listener and spawns the accept loop. Returns when
// the listener is bound (or fails to bind). The receiver itself runs
// in goroutines added to wg.
func (s *TCPJSONReceiver) Start(ctx context.Context, wg *sync.WaitGroup) error {
	ln, err := net.Listen("tcp", s.cfg.Listen)
	if err != nil {
		return err
	}
	s.listener = ln

	wg.Add(1)
	go func() {
		defer wg.Done()
		s.log.Info("tcp_json listening",
			"addr", s.cfg.Listen,
			"profile", s.cfg.Profile,
			"allowed_ips", len(s.cfg.AllowedIPs),
			"max_message_bytes", s.maxLine)
		for {
			conn, err := ln.Accept()
			if err != nil {
				select {
				case <-ctx.Done():
					return
				default:
					s.log.Error("tcp_json accept", "err", err)
					continue
				}
			}

			// IP allowlist check happens BEFORE we spawn a goroutine
			// or do any work for the connection. Rejected connections
			// are immediately closed.
			if !s.isAllowed(conn.RemoteAddr()) {
				s.log.Warn("tcp_json connection rejected (not in allowed_ips)",
					"remote", conn.RemoteAddr().String())
				_ = conn.Close()
				continue
			}

			wg.Add(1)
			go s.handleConn(ctx, wg, conn)
		}
	}()

	// Close listener when ctx is canceled - unblocks Accept.
	wg.Add(1)
	go func() {
		defer wg.Done()
		<-ctx.Done()
		_ = ln.Close()
	}()

	return nil
}

// isAllowed returns true if the remote address is in any of the
// configured allowed_ips CIDRs.
func (s *TCPJSONReceiver) isAllowed(addr net.Addr) bool {
	host, _, err := net.SplitHostPort(addr.String())
	if err != nil {
		return false
	}
	ip := net.ParseIP(host)
	if ip == nil {
		return false
	}
	for _, n := range s.allowedNets {
		if n.Contains(ip) {
			return true
		}
	}
	return false
}

// handleConn reads newline-delimited JSON lines from one connection
// until EOF or context cancellation. Each line becomes one RawEvent
// dispatched to the pipeline.
func (s *TCPJSONReceiver) handleConn(ctx context.Context, wg *sync.WaitGroup, conn net.Conn) {
	defer wg.Done()
	defer conn.Close()

	remoteIP := remoteIPOf(conn)
	remoteIPStr := ""
	if remoteIP != nil {
		remoteIPStr = remoteIP.String()
	}

	s.log.Debug("tcp_json connection opened", "remote", remoteIPStr)

	// bufio.Scanner with explicit buffer cap. Default 64K is too small
	// for some Ansible recap events with many hosts.
	scanner := bufio.NewScanner(conn)
	scanner.Buffer(make([]byte, 0, 64*1024), s.maxLine)

	msgCount := 0

	for {
		// Re-check context before each line.
		select {
		case <-ctx.Done():
			s.log.Debug("tcp_json connection closing (ctx done)", "remote", remoteIPStr, "messages", msgCount)
			return
		default:
		}

		// Read deadline: 60s per line. Senders that hold the socket
		// open with no data for >60s get disconnected. Reset on each
		// successful read. The Ansible callback sends at least once
		// per task, so this only kicks in for misbehaving clients.
		_ = conn.SetReadDeadline(time.Now().Add(60 * time.Second))

		if !scanner.Scan() {
			// EOF, deadline, or scan error. All terminal for this
			// connection.
			if err := scanner.Err(); err != nil && !errors.Is(err, io.EOF) {
				// Don't log timeouts as errors - they're expected when
				// connections are idle.
				var nerr net.Error
				if errors.As(err, &nerr) && nerr.Timeout() {
					s.log.Debug("tcp_json connection idle timeout", "remote", remoteIPStr)
				} else {
					s.log.Debug("tcp_json read error", "remote", remoteIPStr, "err", err)
				}
			}
			s.log.Debug("tcp_json connection closed", "remote", remoteIPStr, "messages", msgCount)
			return
		}

		line := scanner.Bytes()
		if len(line) == 0 {
			continue // empty line - benign, sender may have sent a stray \n
		}

		// Copy the line - scanner reuses its buffer for the next call,
		// but the pipeline holds the raw bytes until the event is
		// fully processed.
		body := make([]byte, len(line))
		copy(body, line)

		// Trace capture (pre-pipeline). nil-safe.
		s.tracer.CaptureTCPJSON(remoteIPStr, body)

		// Construct the event. Source string is "tcp_json:<port>"
		// (matches SMTP's "smtp-25" convention). Profile binding
		// comes from the receiver config - one profile per listener.
		ev := event.New("tcp_json:"+s.cfg.Listen, body)
		if remoteIP != nil {
			ev.EntityIP = remoteIP
			ev.Attributes["src_ip"] = remoteIPStr
			ev.Attributes["origin_id"] = remoteIPStr
		}
		metrics.EventsReceived.WithLabelValues("tcp_json:" + s.cfg.Profile).Inc()

		select {
		case s.rawCh <- &pipeline.RawEvent{Profile: s.cfg.Profile, Event: ev}:
			msgCount++
		case <-ctx.Done():
			return
		}
	}
}
