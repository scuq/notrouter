// Command loadtest fires synthetic webhook events at notrouter to validate
// throughput. Designed to drive the original 1000 msg/s goal.
//
// Usage:
//
//	go run ./cmd/loadtest -url http://localhost:8080/webhook/generic \
//	    -qps 1000 -duration 60s -concurrency 50
//
// Each event is a small JSON body with a unique entity ID so dedup doesn't
// short-circuit the test. The tool reports observed throughput, p50/p95/p99
// latency, and failure counts.
package main

import (
	"bytes"
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"net/http"
	"os"
	"sort"
	"sync"
	"sync/atomic"
	"time"
)

func main() {
	var (
		url         = flag.String("url", "http://localhost:8080/webhook/generic", "target URL")
		qps         = flag.Int("qps", 1000, "target events per second")
		duration    = flag.Duration("duration", 30*time.Second, "test duration")
		concurrency = flag.Int("concurrency", 50, "concurrent HTTP workers")
		warmup      = flag.Duration("warmup", 2*time.Second, "warmup time before measuring")
	)
	flag.Parse()

	fmt.Printf("loadtest: %d qps for %s with %d workers -> %s\n", *qps, *duration, *concurrency, *url)
	fmt.Printf("  warmup: %s (samples discarded)\n", *warmup)

	// Bound the work generator with a ticker to enforce QPS; workers pull
	// from a channel. This decouples timing from worker scheduling and gives
	// us back-pressure visibility - if workers can't keep up, the channel
	// fills and we count it as a producer-side overrun.
	jobs := make(chan job, *concurrency*4)

	client := &http.Client{
		Timeout: 5 * time.Second,
		Transport: &http.Transport{
			MaxIdleConns:        *concurrency * 2,
			MaxIdleConnsPerHost: *concurrency * 2,
			IdleConnTimeout:     30 * time.Second,
		},
	}

	stats := &stats{}

	ctx, cancel := context.WithTimeout(context.Background(), *duration+*warmup+5*time.Second)
	defer cancel()

	// Warmup window threshold; samples before this are tracked separately
	// and not included in the final percentile/throughput numbers.
	warmupUntil := time.Now().Add(*warmup)

	var wg sync.WaitGroup
	for i := 0; i < *concurrency; i++ {
		wg.Add(1)
		go worker(ctx, &wg, client, *url, jobs, stats, warmupUntil)
	}

	// Producer: tick at qps rate, push jobs. If the channel is full we count
	// it as a backpressure event - the consumer is the limit, not the network.
	producerDone := make(chan struct{})
	go func() {
		defer close(producerDone)
		interval := time.Second / time.Duration(*qps)
		// time.Ticker rounds DOWN intervals; for fast rates we use a manual
		// sleep loop to keep timing tighter.
		next := time.Now().Add(*warmup)
		end := next.Add(*duration)
		seq := uint64(0)
		for time.Now().Before(end) {
			select {
			case <-ctx.Done():
				return
			default:
			}
			now := time.Now()
			if now.Before(next) {
				time.Sleep(next.Sub(now))
			}
			next = next.Add(interval)
			seq++
			j := job{seq: seq, sentAt: time.Now()}
			select {
			case jobs <- j:
			default:
				atomic.AddUint64(&stats.producerOverruns, 1)
			}
		}
	}()

	<-producerDone
	close(jobs)
	wg.Wait()

	stats.report(*duration, *qps)

	if atomic.LoadUint64(&stats.failures) > 0 {
		os.Exit(1)
	}
}

type job struct {
	seq    uint64
	sentAt time.Time
}

type stats struct {
	successes        uint64
	failures         uint64
	producerOverruns uint64

	mu       sync.Mutex
	latencies []time.Duration // measured-window only
}

func (s *stats) record(d time.Duration, success bool, inWindow bool) {
	if success {
		atomic.AddUint64(&s.successes, 1)
	} else {
		atomic.AddUint64(&s.failures, 1)
	}
	if inWindow && success {
		s.mu.Lock()
		s.latencies = append(s.latencies, d)
		s.mu.Unlock()
	}
}

func (s *stats) report(target time.Duration, qps int) {
	s.mu.Lock()
	lat := append([]time.Duration(nil), s.latencies...)
	s.mu.Unlock()
	sort.Slice(lat, func(i, j int) bool { return lat[i] < lat[j] })

	successes := atomic.LoadUint64(&s.successes)
	failures := atomic.LoadUint64(&s.failures)
	overruns := atomic.LoadUint64(&s.producerOverruns)

	// Approximate observed QPS from samples in the measured window.
	observed := float64(len(lat)) / target.Seconds()

	fmt.Printf("\n--- results ---\n")
	fmt.Printf("target:    %d qps for %s\n", qps, target)
	fmt.Printf("observed:  %.1f qps (%d samples in measured window)\n", observed, len(lat))
	fmt.Printf("success:   %d total (%d in window)\n", successes, len(lat))
	fmt.Printf("failures:  %d\n", failures)
	fmt.Printf("overruns:  %d (producer couldn't queue, workers maxed out)\n", overruns)
	if len(lat) > 0 {
		fmt.Printf("latency:   p50=%s p95=%s p99=%s max=%s\n",
			pct(lat, 0.50), pct(lat, 0.95), pct(lat, 0.99), lat[len(lat)-1])
	}
}

func pct(sorted []time.Duration, q float64) time.Duration {
	if len(sorted) == 0 {
		return 0
	}
	idx := int(float64(len(sorted)-1) * q)
	return sorted[idx]
}

func worker(ctx context.Context, wg *sync.WaitGroup, client *http.Client, url string, jobs <-chan job, st *stats, warmupUntil time.Time) {
	defer wg.Done()
	for j := range jobs {
		select {
		case <-ctx.Done():
			return
		default:
		}
		body, _ := json.Marshal(map[string]interface{}{
			// Unique entity per request so dedup doesn't drop our test
			// traffic and skew results.
			"entity": fmt.Sprintf("loadtest-%d", j.seq),
			"state":  "DOWN",
			"seq":    j.seq,
		})

		start := time.Now()
		req, _ := http.NewRequestWithContext(ctx, "POST", url, bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		resp, err := client.Do(req)
		elapsed := time.Since(start)

		ok := err == nil && resp.StatusCode >= 200 && resp.StatusCode < 300
		if resp != nil {
			resp.Body.Close()
		}

		st.record(elapsed, ok, time.Now().After(warmupUntil))
	}
}
