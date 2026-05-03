package receivers

import (
	"context"
	"log/slog"
	"net"
	"sync"

	"github.com/scuq/notrouter/internal/event"
	"github.com/scuq/notrouter/internal/metrics"
	"github.com/scuq/notrouter/internal/pipeline"
)

type SyslogUDPReceiver struct {
	addr  string
	rawCh chan<- *pipeline.RawEvent
	log   *slog.Logger
	conn  net.PacketConn
}

func NewSyslogUDP(addr string, rawCh chan<- *pipeline.RawEvent, log *slog.Logger) *SyslogUDPReceiver {
	return &SyslogUDPReceiver{addr: addr, rawCh: rawCh, log: log}
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
