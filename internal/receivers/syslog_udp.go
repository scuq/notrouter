package receivers

import (
	"context"
	"log/slog"
	"net"
	"sync"

	"github.com/scuq/notrouter/internal/event"
	"github.com/scuq/notrouter/internal/metrics"
	"github.com/scuq/notrouter/internal/pipeline"
	"github.com/scuq/notrouter/internal/trace"
)

type SyslogUDPReceiver struct {
	addr   string
	rawCh  chan<- *pipeline.RawEvent
	log    *slog.Logger
	conn   net.PacketConn
	filter *SyslogFilter // nil means pass everything (legacy/disabled behavior)
	tracer *trace.Tracer
}

// SetTracer wires in an optional trace.Tracer. nil-safe.
func (s *SyslogUDPReceiver) SetTracer(t *trace.Tracer) {
	if s != nil {
		s.tracer = t
	}
}

func NewSyslogUDP(addr string, rawCh chan<- *pipeline.RawEvent, log *slog.Logger) *SyslogUDPReceiver {
	return &SyslogUDPReceiver{addr: addr, rawCh: rawCh, log: log}
}

// NewSyslogUDPWithFilter wires in the early-drop filter. If filter is
// nil, behaves identically to NewSyslogUDP.
func NewSyslogUDPWithFilter(addr string, rawCh chan<- *pipeline.RawEvent, filter *SyslogFilter, log *slog.Logger) *SyslogUDPReceiver {
	return &SyslogUDPReceiver{addr: addr, rawCh: rawCh, log: log, filter: filter}
}

func (s *SyslogUDPReceiver) Name() string { return "syslog-udp" }

func (s *SyslogUDPReceiver) Start(ctx context.Context, wg *sync.WaitGroup) error {
	conn, err := net.ListenPacket("udp", s.addr)
	if err != nil {
		return err
	}
	s.conn = conn

	wg.Add(1)
	go func() {
		defer wg.Done()
		s.log.Info("syslog-udp listening", "addr", s.addr)
		// 64KB is the practical UDP datagram max; syslog rarely exceeds 8KB
		// but we size for the ceiling to avoid silent truncation.
		buf := make([]byte, 65536)
		for {
			n, addr, err := conn.ReadFrom(buf)
			if err != nil {
				select {
				case <-ctx.Done():
					return
				default:
					s.log.Error("syslog-udp read", "err", err)
					continue
				}
			}

			// Early-drop filter runs against the raw datagram bytes BEFORE
			// any allocation. On a 99% drop workload at 50k msg/s this
			// avoids 49,500 event allocations per second + their downstream
			// pipeline work. Filter returns true (admit) when nil.
			if !s.filter.Allow(buf[:n]) {
				continue
			}

			// Trace capture (post-filter, pre-allocation). Captures only
			// admitted datagrams - useful for debugging "what got past my
			// filter." nil-safe.
			srcStr := "unknown"
			if udpAddr, ok := addr.(*net.UDPAddr); ok {
				srcStr = udpAddr.IP.String()
			}
			s.tracer.CaptureSyslogUDP(srcStr, buf[:n])

			// Now pay the allocation cost - we know this message is going
			// to enter the pipeline.
			payload := make([]byte, n)
			copy(payload, buf[:n])

			ev := event.New("syslog-udp", payload)
			if udpAddr, ok := addr.(*net.UDPAddr); ok {
				ev.EntityIP = udpAddr.IP
				ev.Attributes["src_ip"] = udpAddr.IP.String()
			}

			metrics.EventsReceived.WithLabelValues("syslog-udp").Inc()

			select {
			case s.rawCh <- &pipeline.RawEvent{Profile: "syslog", Event: ev}:
			case <-ctx.Done():
				return
			default:
				// UDP is lossy by spec; we honor that under backpressure.
			}
		}
	}()

	wg.Add(1)
	go func() {
		defer wg.Done()
		<-ctx.Done()
		_ = conn.Close()
	}()

	return nil
}
