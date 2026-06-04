package parser

import (
	"encoding/json"
	"fmt"
	"sort"
	"strings"
)

// renderAnsibleRecapDots produces a multi-line string with one host
// per line, prefixed by a colored dot indicating health:
//
//   🟢 host-name-1
//   🔴 host-name-2
//   🟡 host-name-3
//
// failures > 0 -> red, unreachable > 0 -> yellow, otherwise green.
// Hosts are sorted alphabetically for stable output (Go maps don't
// preserve order; consumers like dedup keys benefit from determinism).
//
// recapJSON is the raw JSON-encoded recap string (typically the value
// of ansible_result from a Logstash callback event).
//
// Returns "" on parse failure - caller treats absence as "skip the
// attribute" rather than erroring.
func renderAnsibleRecapDots(recapJSON string) string {
	hosts, ok := parseRecapHosts(recapJSON)
	if !ok || len(hosts) == 0 {
		return ""
	}

	names := sortedHostNames(hosts)
	lines := make([]string, 0, len(names))
	for _, name := range names {
		stats := hosts[name]
		lines = append(lines, hostDot(stats)+" "+name)
	}
	return strings.Join(lines, "\n")
}

// renderAnsibleRecapTable produces the classic PLAY RECAP table:
//
//   host-1               : ok=3   changed=0  unreachable=0  failed=0
//   host-2               : ok=12  changed=2  unreachable=0  failed=1
//
// Host column is left-padded to hostWidth (default 20).
// Counter fields are right-padded for column alignment.
//
// Same sort order and parse semantics as renderAnsibleRecapDots.
func renderAnsibleRecapTable(recapJSON string, hostWidth int) string {
	if hostWidth <= 0 {
		hostWidth = 20
	}

	hosts, ok := parseRecapHosts(recapJSON)
	if !ok || len(hosts) == 0 {
		return ""
	}

	names := sortedHostNames(hosts)
	lines := make([]string, 0, len(names))
	for _, name := range names {
		s := hosts[name]
		// "%-Ns" left-justifies in a field width N. The numeric fields
		// use "%-3d" to right-pad to width 3 (matches Python forwarder).
		lines = append(lines, fmt.Sprintf(
			"%-*s : ok=%-3d changed=%-3d unreachable=%-3d failed=%-3d",
			hostWidth, name,
			s.OK, s.Changed, s.Unreachable, s.Failures,
		))
	}
	return strings.Join(lines, "\n")
}

// recapHostStats - per-host counts parsed from ansible_result.
// Field names mirror Ansible/Logstash naming. We accept both
// "failures" (Logstash output) and "failed" (some older versions) -
// matching the Python forwarder's defensive lookup.
type recapHostStats struct {
	OK          int
	Changed     int
	Failures    int
	Unreachable int
}

// hostDot picks the emoji for a host based on failure state.
// Mirrors Python: failed > 0 -> red, unreachable > 0 -> yellow, else green.
func hostDot(s recapHostStats) string {
	if s.Failures > 0 {
		return "🔴"
	}
	if s.Unreachable > 0 {
		return "🟡"
	}
	return "🟢"
}

// parseRecapHosts decodes the JSON-encoded recap and normalizes into
// a host -> stats map. Tolerant of:
//   - missing fields (default to 0)
//   - "failures" vs "failed" field names
//   - values arriving as strings, floats, or ints (Go's JSON decoder
//     produces float64 for numbers by default)
//
// Returns (nil, false) on any unmarshal failure.
func parseRecapHosts(recapJSON string) (map[string]recapHostStats, bool) {
	if recapJSON == "" {
		return nil, false
	}
	var raw map[string]map[string]interface{}
	if err := json.Unmarshal([]byte(recapJSON), &raw); err != nil {
		return nil, false
	}
	out := make(map[string]recapHostStats, len(raw))
	for host, stats := range raw {
		out[host] = recapHostStats{
			OK:          toInt(stats["ok"]),
			Changed:     toInt(stats["changed"]),
			Failures:    toIntFirstNonZero(stats["failures"], stats["failed"]),
			Unreachable: toInt(stats["unreachable"]),
		}
	}
	return out, true
}

// sortedHostNames returns map keys in alphabetical order for stable
// rendering. Required for dedup consistency and human readability.
func sortedHostNames(hosts map[string]recapHostStats) []string {
	names := make([]string, 0, len(hosts))
	for n := range hosts {
		names = append(names, n)
	}
	sort.Strings(names)
	return names
}

// toInt coerces a JSON-decoded value into an int. JSON numbers are
// float64; strings are tolerated for safety.
func toInt(v interface{}) int {
	switch x := v.(type) {
	case float64:
		return int(x)
	case int:
		return x
	case string:
		var n int
		fmt.Sscanf(x, "%d", &n)
		return n
	}
	return 0
}

// toIntFirstNonZero returns the first of a,b that converts to a
// non-zero int. If both are zero/missing, returns 0. Used for the
// failures/failed field-name variance.
func toIntFirstNonZero(a, b interface{}) int {
	if n := toInt(a); n != 0 {
		return n
	}
	return toInt(b)
}
