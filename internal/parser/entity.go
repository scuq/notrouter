package parser

import (
	"context"
	"encoding/json"
	"log/slog"
	"regexp"
	"strings"
	"sync"

	"github.com/scuq/notrouter/internal/config"
	"github.com/scuq/notrouter/internal/jsonpath"
	"github.com/scuq/notrouter/internal/metrics"
	"github.com/scuq/notrouter/internal/pipeline"
)

// compiledProfile holds pre-parsed extraction rules for a single profile.
// Built once at startup; read-only at runtime.
type compiledProfile struct {
	name                 string
	entityFromJSON       string
	entityRegex          *regexp.Regexp
	entityField          string // "hostname" | "src_ip" | "" (for syslog header lookups)
	entityFromJSONString string // outer-JSON path; value is a JSON-encoded string
	entitySelect         string // sub-path inside the parsed inner JSON
}

type EntityResolver struct {
	in       <-chan *pipeline.RawEvent
	out      chan<- *pipeline.RawEvent
	profiles map[string]*compiledProfile
	workers  int
	log      *slog.Logger
}

func NewEntityResolver(
	in <-chan *pipeline.RawEvent,
	out chan<- *pipeline.RawEvent,
	profileCfgs map[string]config.ProfileConfig,
	workers int,
	log *slog.Logger,
) (*EntityResolver, error) {
	profiles := make(map[string]*compiledProfile, len(profileCfgs)+1)

	for name, pc := range profileCfgs {
		cp := &compiledProfile{
			name:                 name,
			entityFromJSON:       pc.Entity.FromJSON,
			entityField:          pc.Entity.FromField,
			entityFromJSONString: pc.Entity.FromJSONString,
			entitySelect:         pc.Entity.Select,
		}
		if pc.Entity.FromRegex != "" {
			re, err := regexp.Compile(pc.Entity.FromRegex)
			if err != nil {
				return nil, err
			}
			cp.entityRegex = re
		}
		profiles[name] = cp
	}

	// Implicit "syslog" profile: prefer parsed hostname, fall back to src IP.
	if _, ok := profiles["syslog"]; !ok {
		profiles["syslog"] = &compiledProfile{
			name:        "syslog",
			entityField: "hostname",
		}
	}

	return &EntityResolver{
		in:       in,
		out:      out,
		profiles: profiles,
		workers:  workers,
		log:      log,
	}, nil
}

func (r *EntityResolver) Name() string { return "entity-resolver" }

func (r *EntityResolver) Run(ctx context.Context, wg *sync.WaitGroup) {
	defer wg.Done()
	var workerWg sync.WaitGroup
	for i := 0; i < r.workers; i++ {
		workerWg.Add(1)
		go r.worker(ctx, &workerWg)
	}
	workerWg.Wait()
	close(r.out)
}

func (r *EntityResolver) worker(ctx context.Context, wg *sync.WaitGroup) {
	defer wg.Done()
	for {
		select {
		case <-ctx.Done():
			return
		case raw, ok := <-r.in:
			if !ok {
				return
			}
			if !r.resolve(raw) {
				metrics.EventsDropped.WithLabelValues("entity_unresolved").Inc()
				r.log.Warn("entity unresolved",
					"source", raw.Event.Source,
					"profile", raw.Profile,
					"src_ip", raw.Event.Attributes["src_ip"],
					"payload", truncate(raw.Event.Raw, 200))
				continue
			}
			metrics.EventsResolved.WithLabelValues(raw.Event.Source).Inc()

			select {
			case r.out <- raw:
			case <-ctx.Done():
				return
			}
		}
	}
}

// resolve dispatches by raw.Profile. For syslog it tries to parse the message
// and lift the hostname; on parse failure it passes the event through anyway
// (option B from the design discussion) with a synthetic syslog-malformed
// topic and src_ip as entity.
func (r *EntityResolver) resolve(raw *pipeline.RawEvent) bool {
	profile, ok := r.profiles[raw.Profile]
	if !ok {
		// Unknown profile - fall back to "use what we already have".
		return r.fallback(raw)
	}

	// Syslog has its own pre-resolution step: try to parse, populate
	// attributes, and use the parsed hostname as the primary entity source.
	if isSyslogSource(raw.Event.Source) {
		r.preparseSyslog(raw)
	}

	// 1. Try JSON-path on the body (for webhooks).
	if profile.entityFromJSON != "" {
		if entity, ok := extractFromJSON(raw.Event.Raw, profile.entityFromJSON); ok && entity != "" {
			raw.Event.Entity = entity
			return true
		}
	}

	// 2. Try JSON-string deref: read an outer JSON field whose value is
	//    itself a JSON-encoded string, parse it, then JSONPath into it.
	//    Used for Logstash-style events where ansible_pre_command_output
	//    is a JSON string. Mirrors the attribute extractor's behavior.
	if profile.entityFromJSONString != "" {
		if entity, ok := extractFromJSONStringEntity(raw.Event.Raw, profile.entityFromJSONString, profile.entitySelect); ok && entity != "" {
			raw.Event.Entity = entity
			return true
		}
	}

	// 3. Try a named field already in attributes (e.g. parsed syslog hostname).
	if profile.entityField != "" {
		if v, ok := raw.Event.Attributes[profile.entityField]; ok && v != "" {
			raw.Event.Entity = v
			return true
		}
	}

	// 4. Try a regex against the raw payload.
	if profile.entityRegex != nil {
		if m := profile.entityRegex.FindSubmatch(raw.Event.Raw); m != nil {
			// If there's a capturing group, use it; otherwise the whole match.
			if len(m) > 1 {
				raw.Event.Entity = string(m[1])
			} else {
				raw.Event.Entity = string(m[0])
			}
			return true
		}
	}

	return r.fallback(raw)
}

// fallback uses src_ip if available. Returns true if we got *something*.
func (r *EntityResolver) fallback(raw *pipeline.RawEvent) bool {
	if raw.Event.Entity != "" {
		return true
	}
	if ip := raw.Event.Attributes["src_ip"]; ip != "" {
		raw.Event.Entity = ip
		return true
	}
	if raw.Event.EntityIP != nil {
		raw.Event.Entity = raw.Event.EntityIP.String()
		return true
	}
	return false
}

func isSyslogSource(s string) bool {
	return strings.HasPrefix(s, "syslog-")
}

// preparseSyslog runs the syslog parser against the raw payload and stuffs
// the parsed fields into Event.Attributes so the main resolution path and
// the normalizer can use them. On parse error we set syslog_malformed=true
// and DON'T abort - that's option B (passthrough).
func (r *EntityResolver) preparseSyslog(raw *pipeline.RawEvent) {
	parsed, err := ParseSyslog(string(raw.Event.Raw))
	if err != nil {
		raw.Event.Attributes["syslog_malformed"] = "true"
		raw.Event.Attributes["syslog_parse_error"] = err.Error()
		return
	}

	if parsed.Hostname != "" {
		raw.Event.Attributes["hostname"] = parsed.Hostname
	}
	if parsed.AppName != "" {
		raw.Event.Attributes["app"] = parsed.AppName
	}
	if parsed.ProcID != "" {
		raw.Event.Attributes["procid"] = parsed.ProcID
	}
	if parsed.MsgID != "" {
		raw.Event.Attributes["msgid"] = parsed.MsgID
	}
	raw.Event.Attributes["syslog_facility"] = severityFacility(parsed.Facility, "facility")
	raw.Event.Attributes["syslog_severity"] = severityFacility(parsed.Severity, "severity")
	raw.Event.Attributes["syslog_format"] = parsed.Format
	if parsed.Message != "" {
		raw.Event.Attributes["msg"] = parsed.Message
	}
	if !parsed.Timestamp.IsZero() {
		raw.Event.Timestamp = parsed.Timestamp
	}
}

func severityFacility(n int, _ string) string {
	// Stringified for use in templates and matchers. Names could be added
	// later; numeric is unambiguous and small.
	return itoa(n)
}

func itoa(n int) string {
	// Tiny helper to avoid importing strconv just for this.
	if n == 0 {
		return "0"
	}
	var buf [4]byte
	i := len(buf)
	for n > 0 {
		i--
		buf[i] = byte('0' + n%10)
		n /= 10
	}
	return string(buf[i:])
}

// extractFromJSON unmarshals raw and runs jsonpath.GetString. Returns "" on
// any error so callers can fall through to the next strategy.
func extractFromJSON(raw []byte, path string) (string, bool) {
	var v interface{}
	if err := json.Unmarshal(raw, &v); err != nil {
		return "", false
	}
	return jsonpath.GetString(v, path)
}

// extractFromJSONStringEntity is the entity-resolver equivalent of the
// attribute extractor's from_json_string + select. Reads an outer JSON
// field whose value is a JSON-encoded string, parses it, then extracts
// a sub-path. Empty select means "return the stringified parsed object"
// (rarely useful here but symmetric with the attribute version).
//
// Returns ("", false) on any failure (outer path miss, inner parse
// error, inner path miss) - the caller falls through to the next
// entity strategy.
func extractFromJSONStringEntity(rawBody []byte, outerPath, selectPath string) (string, bool) {
	innerRaw, ok := extractFromJSON(rawBody, outerPath)
	if !ok || innerRaw == "" {
		return "", false
	}
	var inner interface{}
	if err := json.Unmarshal([]byte(innerRaw), &inner); err != nil {
		return "", false
	}
	if selectPath == "" {
		if b, err := json.Marshal(inner); err == nil {
			return string(b), true
		}
		return "", false
	}
	// inner JSONPath - use jsonpath.GetString for symmetric behavior with
	// the attribute extractor's stringification of scalar fields.
	s, ok := jsonpath.GetString(inner, selectPath)
	if !ok || s == "" {
		return "", false
	}
	return s, true
}

func truncate(b []byte, n int) string {
	if len(b) <= n {
		return string(b)
	}
	return string(b[:n]) + "..."
}
