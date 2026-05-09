package receivers

import (
	"bufio"
	"context"
	"errors"
	"io"
	"log/slog"
	"net"
	"strconv"
	"sync"

	"github.com/scuq/notrouter/internal/event"
	"github.com/scuq/notrouter/internal/metrics"
	"github.com/scuq/notrouter/internal/pipeline"
	"github.com/scuq/notrouter/internal/trace"
)

// Per RFC6587 a TCP syslog stream uses one of two framings:
//
//   1. octet-counted:    "<DIGITS> <MSG>"  e.g.  "47 <134>Oct 11 ..."
//   2. non-transparent:  "<MSG>\n"           (LF terminator)
//
// We auto-detect per-message: if the leading byte is an ASCII digit we
// assume octet-counted; otherwise we read until \n. Real-world senders
// pick one and stick with it for the lifetime of the connection.

const (
	maxFrameBytes = 1 << 20 // 1 MiB hard cap per message
)

type SyslogTCPReceiver struct {
	addr     string
	rawCh    chan<- *pipeline.RawEvent
	log      *slog.Logger
	listener net.Listener
	filter   *SyslogFilter
	tracer   *trace.Tracer
}

// SetTracer wires in an optional trace.Tracer. nil-safe.
func (s *SyslogTCPReceiver) SetTracer(t *trace.Tracer) {
	if s != nil {
		s.tracer = t
	}
}

func NewSyslogTCP(addr string, rawCh chan<- *pipeline.RawEvent, log *slog.Logger) *SyslogTCPReceiver {
	return &SyslogTCPReceiver{addr: addr, rawCh: rawCh, log: log}
}

func NewSyslogTCPWithFilter(addr string, rawCh chan<- *pipeline.RawEvent, filter *SyslogFilter, log *slog.Logger) *SyslogTCPReceiver {
	return &SyslogTCPReceiver{addr: addr, rawCh: rawCh, log: log, filter: filter}
}

func (s *SyslogTCPReceiver) Name() string { return "syslog-tcp" }

func (s *SyslogTCPReceiver) Start(ctx context.Context, wg *sync.WaitGroup) error {
	ln, err := net.Listen("tcp", s.addr)
	if err != nil {
		return err
	}
	s.listener = ln

	wg.Add(1)
	go func() {
		defer wg.Done()
		s.log.Info("syslog-tcp listening", "addr", s.addr)
		for {
			conn, err := ln.Accept()
			if err != nil {
				select {
				case <-ctx.Done():
					return
				default:
					s.log.Error("syslog-tcp accept", "err", err)
					continue
				}
			}
			wg.Add(1)
			go s.handleConn(ctx, wg, conn)
		}
	}()

	wg.Add(1)
	go func() {
		defer wg.Done()
		<-ctx.Done()
		_ = ln.Close()
	}()

	return nil
}

func (s *SyslogTCPReceiver) handleConn(ctx context.Context, wg *sync.WaitGroup, conn net.Conn) {
	defer wg.Done()
	defer conn.Close()

	br := bufio.NewReaderSize(conn, 64*1024)
	remoteIP := remoteIPOf(conn)

	for {
		select {
		case <-ctx.Done():
			return
		default:
		}

		frame, err := readOneFrame(br)
		if err != nil {
			if !errors.Is(err, io.EOF) {
				s.log.Debug("syslog-tcp read", "err", err, "remote", conn.RemoteAddr())
			}
			return
		}
		if len(frame) == 0 {
			continue
		}

		// Filter runs before event allocation, same as UDP path. The
		// frame slice is bufio's internal buffer (or freshly read for
		// octet-counted) - safe to pass to filter, no copy needed.
		if !s.filter.Allow(frame) {
			continue
		}

		// Trace capture (post-filter). nil-safe.
		srcStr := "unknown"
		if remoteIP != nil {
			srcStr = remoteIP.String()
		}
		s.tracer.CaptureSyslogTCP(srcStr, frame)

		ev := event.New("syslog-tcp", frame)
		if remoteIP != nil {
			ev.EntityIP = remoteIP
			ev.Attributes["src_ip"] = remoteIP.String()
			ev.Attributes["origin_id"] = remoteIP.String()
		}
		metrics.EventsReceived.WithLabelValues("syslog-tcp").Inc()

		select {
		case s.rawCh <- &pipeline.RawEvent{Profile: "syslog", Event: ev}:
		case <-ctx.Done():
			return
		}
	}
}

// readOneFrame returns one complete syslog message. It auto-detects framing
// per message: leading ASCII digit -> octet-counted; otherwise LF-terminated.
func readOneFrame(br *bufio.Reader) ([]byte, error) {
	// Peek one byte without consuming to decide framing.
	first, err := br.Peek(1)
	if err != nil {
		return nil, err
	}

	if first[0] >= '0' && first[0] <= '9' {
		return readOctetCounted(br)
	}
	return readLineFrame(br)
}

func readOctetCounted(br *bufio.Reader) ([]byte, error) {
	// Read length digits up to the space separator.
	var lenBuf [12]byte
	n := 0
	for n < len(lenBuf) {
		b, err := br.ReadByte()
		if err != nil {
			return nil, err
		}
		if b == ' ' {
			break
		}
		if b < '0' || b > '9' {
			return nil, errors.New("octet-count: non-digit")
		}
		lenBuf[n] = b
		n++
	}
	if n == 0 {
		return nil, errors.New("octet-count: empty length")
	}
	length, err := strconv.Atoi(string(lenBuf[:n]))
	if err != nil {
		return nil, err
	}
	if length <= 0 || length > maxFrameBytes {
		return nil, errors.New("octet-count: bad length")
	}
	buf := make([]byte, length)
	if _, err := io.ReadFull(br, buf); err != nil {
		return nil, err
	}
	return buf, nil
}

func readLineFrame(br *bufio.Reader) ([]byte, error) {
	// bufio.Reader.ReadBytes copies the data; it stops at and includes '\n'.
	// We strip the trailing '\n' (and any '\r' before it).
	line, err := br.ReadBytes('\n')
	if err != nil && len(line) == 0 {
		return nil, err
	}
	if len(line) > 0 && line[len(line)-1] == '\n' {
		line = line[:len(line)-1]
	}
	if len(line) > 0 && line[len(line)-1] == '\r' {
		line = line[:len(line)-1]
	}
	return line, nil
}

func remoteIPOf(conn net.Conn) net.IP {
	if tcp, ok := conn.RemoteAddr().(*net.TCPAddr); ok {
		return tcp.IP
	}
	return nil
}
