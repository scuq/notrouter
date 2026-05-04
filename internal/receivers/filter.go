package receivers

import (
	"bytes"
	"log/slog"
	"sort"
	"strings"
	"sync/atomic"
	"time"

	"github.com/scuq/notrouter/internal/config"
)

// SyslogFilter is the early-drop whitelist applied to raw syslog frames
// (UDP datagrams or TCP-framed messages) before any parsing or pipeline
// allocation. Designed to handle 50k+ msg/s with ~99% drop rates.
//
// Matching strategy: linear scan of bytes.Contains over the needle list.
// At ~50ns per check and modest needle counts (<30) this beats Aho-Corasick
// in code complexity and matches it in throughput. Operators can order
// the patterns YAML to put high-frequency ones first - the match returns
// on first hit, so ordering matters. The drop summary log shows the per-
// needle hit counts so the operator knows how to re-order.
//
// Zero allocation on the hot path: needles are pre-converted to []byte
// at NewSyslogFilter time. bytes.Contains takes []byte input directly,
// the input msg is already a []byte from the receiver, and no string
// conversions happen during Allow().
//
// Thread safety: Allow() is called from many goroutines (one per UDP
// recv, one per TCP connection). Counters use atomic.Uint64. The needle
// list itself is immutable for the filter's lifetime - hot reload builds
// a fresh filter and atomically swaps it.
type SyslogFilter struct {
	enabled         bool
	caseInsensitive bool
	logInterval     time.Duration

	// Patterns parallel to perPatternHits. Index N in patterns maps to
	// index N in perPatternHits. Stored both as []byte (for Allow's
	// zero-alloc path) and as string (for log output).
	needlesBytes [][]byte
	needlesStr   []string

	// totalAdmitted - messages that matched some needle and were passed
	// downstream. totalDropped - messages that matched no needle.
	totalAdmitted atomic.Uint64
	totalDropped  atomic.Uint64

	// Per-needle counters. perPatternHits[i] increments when the i-th
	// needle matched. Total of perPatternHits should equal totalAdmitted.
	perPatternHits []atomic.Uint64

	log *slog.Logger
}

// NewSyslogFilter builds a filter from configuration. Returns nil if
// the filter is disabled or has no patterns - callers should treat nil
// as "pass everything." This keeps the disabled-path branch-free in the
// receiver hot loop (just `if filter == nil`).
//
// If cfg.Enabled is true but IncludePatterns is empty, returns nil with
// a warning log: "filter enabled but no patterns" - the alternative
// (drop everything) would silently lose all syslog traffic on a config
// typo and is not what an operator wanting to enable filtering would
// expect.
func NewSyslogFilter(cfg config.SyslogEarlyFilterConfig, log *slog.Logger) *SyslogFilter {
	if !cfg.Enabled {
		return nil
	}
	if len(cfg.IncludePatterns) == 0 {
		log.Warn("syslog early_filter is enabled but include_patterns is empty - filter disabled (would otherwise drop ALL traffic)")
		return nil
	}

	logInterval := cfg.LogInterval
	if logInterval <= 0 {
		logInterval = 10 * time.Minute
	}

	// De-dup the needle list. Operators sometimes paste the same pattern
	// twice; we don't want it counted twice in the summary log.
	seen := make(map[string]struct{}, len(cfg.IncludePatterns))
	clean := make([]string, 0, len(cfg.IncludePatterns))
	for _, p := range cfg.IncludePatterns {
		p = strings.TrimSpace(p)
		if p == "" {
			continue
		}
		if _, ok := seen[p]; ok {
			continue
		}
		seen[p] = struct{}{}
		clean = append(clean, p)
	}
	if len(clean) == 0 {
		log.Warn("syslog early_filter has no usable patterns after trim/dedup - filter disabled")
		return nil
	}

	f := &SyslogFilter{
		enabled:         true,
		caseInsensitive: cfg.CaseInsensitive,
		logInterval:     logInterval,
		needlesStr:      clean,
		log:             log,
	}
	// Pre-convert to []byte so Allow() is zero-alloc. If case_insensitive,
	// these are the lowercased forms; the input message will also be
	// lowercased per-check (unavoidable - we can't lowercase a stream
	// statically).
	f.needlesBytes = make([][]byte, len(clean))
	for i, n := range clean {
		if cfg.CaseInsensitive {
			f.needlesBytes[i] = []byte(strings.ToLower(n))
		} else {
			f.needlesBytes[i] = []byte(n)
		}
	}
	f.perPatternHits = make([]atomic.Uint64, len(clean))

	log.Info("syslog early_filter active",
		"patterns", len(clean),
		"case_insensitive", cfg.CaseInsensitive,
		"log_interval", logInterval)

	return f
}

// Allow tests msg against the whitelist. Returns true if any needle
// matches (admit, increment counters), false if none match (drop, bump
// drop counter). Designed for zero allocation on the dropped path.
//
// Case-sensitive mode is fully zero-alloc: bytes.Contains takes the
// pre-converted needle bytes and the input msg slice directly.
//
// Case-insensitive mode allocates ONE lowercased copy of msg per check.
// At 50k msg/s with average ~500-byte messages, that's ~25MB/s of GC
// pressure - measurable but tolerable. Operators wanting ultimate
// throughput should write their patterns case-sensitively (which most
// firewall syslog actually is - vendor message codes don't change case).
func (f *SyslogFilter) Allow(msg []byte) bool {
	if f == nil || !f.enabled {
		return true
	}

	if f.caseInsensitive {
		lower := bytes.ToLower(msg)
		for i, n := range f.needlesBytes {
			if bytes.Contains(lower, n) {
				f.perPatternHits[i].Add(1)
				f.totalAdmitted.Add(1)
				return true
			}
		}
		f.totalDropped.Add(1)
		return false
	}

	for i, n := range f.needlesBytes {
		if bytes.Contains(msg, n) {
			f.perPatternHits[i].Add(1)
			f.totalAdmitted.Add(1)
			return true
		}
	}
	f.totalDropped.Add(1)
	return false
}

// StartSummaryLogger kicks off a background goroutine that logs a per-
// needle summary every f.logInterval, then resets all counters so the
// next interval reports fresh numbers (matching operator expectation
// of "drops in the last 10 minutes").
//
// Returns a stop function. Caller invokes it at shutdown - the next
// tick will log once more (final partial-interval summary) and exit.
func (f *SyslogFilter) StartSummaryLogger() func() {
	if f == nil || !f.enabled {
		return func() {} // no-op
	}

	stopCh := make(chan struct{})
	go func() {
		t := time.NewTicker(f.logInterval)
		defer t.Stop()
		for {
			select {
			case <-t.C:
				f.logSummaryAndReset()
			case <-stopCh:
				f.logSummaryAndReset()
				return
			}
		}
	}()
	return func() { close(stopCh) }
}

// logSummaryAndReset emits the periodic INFO line with totals and per-
// needle hits, then atomically zeros all counters. Skipped entirely
// (no log line) if both totals are zero - avoids spamming a quiet
// system every 10 minutes with "dropped=0 admitted=0".
func (f *SyslogFilter) logSummaryAndReset() {
	dropped := f.totalDropped.Swap(0)
	admitted := f.totalAdmitted.Swap(0)

	if dropped == 0 && admitted == 0 {
		return
	}

	// Pull per-pattern hits, then swap all to zero. Order of operations
	// matters: read before zero, otherwise we'd lose hits that arrived
	// between read and zero. Loop is short (len(needles)) so contention
	// is minimal.
	type hit struct {
		Pattern  string
		Admitted uint64
	}
	hits := make([]hit, 0, len(f.needlesStr))
	for i := range f.needlesStr {
		c := f.perPatternHits[i].Swap(0)
		if c > 0 {
			hits = append(hits, hit{Pattern: f.needlesStr[i], Admitted: c})
		}
	}
	// Highest-hit patterns first, so the operator's eye lands on the
	// most relevant ones at a glance.
	sort.Slice(hits, func(i, j int) bool {
		return hits[i].Admitted > hits[j].Admitted
	})

	// slog handles structured logging well but per-needle hits are an
	// arbitrary-length list of pairs. We collapse to a single attribute
	// "patterns" with a string representation - keeps the log JSON
	// readable without spawning N attributes.
	patternStrs := make([]string, len(hits))
	for i, h := range hits {
		patternStrs[i] = formatHit(h.Pattern, h.Admitted)
	}
	patterns := strings.Join(patternStrs, ", ")
	if patterns == "" {
		patterns = "(none)"
	}

	f.log.Info("syslog filter summary",
		"interval", f.logInterval,
		"dropped", dropped,
		"admitted", admitted,
		"patterns", patterns)
}

func formatHit(pattern string, admitted uint64) string {
	// Pattern may contain commas, quotes, or other troublesome chars.
	// We wrap in quotes if so. Simple, no escape hell.
	if strings.ContainsAny(pattern, " ,\"") {
		return strings.Join([]string{`"`, pattern, `"`, "=", uintStr(admitted)}, "")
	}
	return strings.Join([]string{pattern, "=", uintStr(admitted)}, "")
}

func uintStr(n uint64) string {
	// strconv.FormatUint without an extra import - well, we already
	// have strconv via syslog_tcp.go, and config.go too. Just use it.
	const decimal = 10
	if n == 0 {
		return "0"
	}
	var buf [20]byte
	i := len(buf)
	for n > 0 {
		i--
		buf[i] = byte('0' + n%decimal)
		n /= decimal
	}
	return string(buf[i:])
}

// SnapshotForState returns the current totals plus the per-needle hits
// without resetting anything. Used by /admin/state for visibility into
// the filter without disturbing the 10-minute rotation.
func (f *SyslogFilter) SnapshotForState() map[string]interface{} {
	if f == nil || !f.enabled {
		return map[string]interface{}{"enabled": false}
	}
	hits := make(map[string]uint64, len(f.needlesStr))
	for i, n := range f.needlesStr {
		hits[n] = f.perPatternHits[i].Load()
	}
	return map[string]interface{}{
		"enabled":          true,
		"case_insensitive": f.caseInsensitive,
		"log_interval":     f.logInterval.String(),
		"patterns":         len(f.needlesStr),
		"current_window": map[string]interface{}{
			"dropped":     f.totalDropped.Load(),
			"admitted":    f.totalAdmitted.Load(),
			"per_pattern": hits,
		},
	}
}
