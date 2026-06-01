package config

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

type Config struct {
	Listen          ListenConfig              `yaml:"listen"`
	Auth            AuthConfig                `yaml:"auth"`
	Receivers       ReceiversConfig           `yaml:"receivers"`
	Profiles        map[string]ProfileConfig  `yaml:"profiles"`
	Dedup           DedupConfig               `yaml:"dedup"`
	Suppressors     []SuppressorConfig        `yaml:"suppressors"`
	Logging         LoggingConfig             `yaml:"logging"`
	PluginInstances map[string]InstanceConfig `yaml:"plugin_instances"`
	Groups          map[string]GroupConfig    `yaml:"groups"`
	Routing         []RoutingRuleConfig       `yaml:"routing"`
	Dispatch        DispatchConfig            `yaml:"dispatch"`
	Pipeline        PipelineConfig            `yaml:"pipeline"`
	Trace           TraceConfig               `yaml:"trace,omitempty"`
	MailParsers     []ParserConfig            `yaml:"mail_parsers,omitempty"`
	SourceAliases   map[string]string         `yaml:"source_aliases,omitempty"`
	Links           map[string]string         `yaml:"links"`

	// path and loadedHash are populated by Load(). Not YAML-tagged so they
	// don't accidentally appear in re-marshaled output.
	path       string `yaml:"-"`
	loadedHash string `yaml:"-"`

	// deprecatedPassword captures any value found in auth.admin.password
	// at parse time. We don't use it for auth anymore (creds.json owns
	// the password since v0.2.1) - we just want to warn the operator
	// at startup if it's still set in their YAML.
	deprecatedPassword string `yaml:"-"`
}

func (c *Config) Path() string       { return c.path }
func (c *Config) LoadedHash() string { return c.loadedHash }

// DeprecatedPasswordSet reports whether auth.admin.password was present
// (non-empty) in the loaded YAML. Used by main() to log a one-shot
// migration warning at startup.
func (c *Config) DeprecatedPasswordSet() bool {
	return c.deprecatedPassword != ""
}

type ListenConfig struct {
	Webhook   string `yaml:"webhook"`
	SyslogUDP string `yaml:"syslog_udp"`
	SyslogTCP string `yaml:"syslog_tcp"`
	Admin     string `yaml:"admin"`
}

type AuthConfig struct {
	Admin AdminAuth `yaml:"admin"`
}

type AdminAuth struct {
	// Username is still used as the literal string compared in basic auth.
	// Defaults to "admin" if unset. Kept in YAML because it's not a secret.
	Username string `yaml:"username"`

	// Password is DEPRECATED as of v0.2.1. The web UI password lives in
	// creds.json (managed via /admin/ui/change-password). Basic auth on
	// /admin/state etc. now uses the same creds.json bcrypt hash.
	//
	// If this field is set in YAML it is ignored at runtime; main()
	// logs a warning so the operator knows to remove it.
	Password string `yaml:"password,omitempty"`

	CredsPath  string        `yaml:"creds_path"`
	SessionTTL time.Duration `yaml:"session_ttl"`
}

type ReceiversConfig struct {
	Webhook WebhookReceiverConfig `yaml:"webhook"`
	Syslog  SyslogReceiverConfig  `yaml:"syslog"`
	SMTP    SMTPReceiverConfig    `yaml:"smtp"`
}

type WebhookReceiverConfig struct {
	Endpoints []WebhookEndpoint `yaml:"endpoints"`

	// RequireAuth, when true, forces every webhook POST to authenticate
	// even if zero webhook keys exist (which would lock everyone out).
	// Default false: enforcement turns on automatically once the first
	// key is minted via the UI - safe rollout, no surprise lockouts.
	RequireAuth bool `yaml:"require_auth"`
	TrustedProxies []string          `yaml:"trusted_proxies,omitempty"`
}

type WebhookEndpoint struct {
	Path    string `yaml:"path"`
	Profile string `yaml:"profile"`
}

// SyslogReceiverConfig holds settings for the UDP and TCP syslog receivers.
// Currently the only configurable behavior is the early-drop filter; the
// listen addresses themselves still come from listen.syslog_udp/tcp at the
// top level (kept there for backwards compat with v0.1.x configs).
type SyslogReceiverConfig struct {
	EarlyFilter SyslogEarlyFilterConfig `yaml:"early_filter"`
}

// SyslogEarlyFilterConfig is a substring whitelist applied to raw syslog
// frames before any parsing or pipeline allocation. Designed for high-
// volume ingestion where the operator only cares about a small set of
// messages (e.g. firewall syslog at 50k msg/s where 99% is uninteresting).
//
// Disabled by default (Enabled: false). When enabled with no patterns,
// the filter disables itself with a startup warning - the alternative
// (drop everything) would silently eat all traffic on a config typo.
type SyslogEarlyFilterConfig struct {
	Enabled         bool          `yaml:"enabled"`
	CaseInsensitive bool          `yaml:"case_insensitive"`
	LogInterval     time.Duration `yaml:"log_interval"`
	IncludePatterns []string      `yaml:"include_patterns"`
}

// SMTPReceiverConfig holds the SMTP receiver's per-port configurations.
// v0.3.0 ships port 25 only. Port 587 (authenticated submission) lands
// in v0.3.3 and will be a sibling block.
type SMTPReceiverConfig struct {
	Port25 SMTPPort25Config `yaml:"port_25"`
}

// SMTPPort25Config configures the unauthenticated SMTP receiver (port 25
// or operator-chosen port). Trust comes from network-level filters: IP
// allowlist via CIDR, RCPT TO exact-match allowlist, and an optional
// FROM allowlist. Empty IP/RCPT lists are treated as DENY-ALL (caller
// must explicitly enumerate what's permitted) - typo-protection against
// accidentally permissive configs.
type SMTPPort25Config struct {
	Enabled         bool     `yaml:"enabled"`
	Listen          string   `yaml:"listen"`            // e.g. ":25" or ":2525"
	Hostname        string   `yaml:"hostname"`          // banner name; defaults to notrouter.local
	AllowedIPs      []string `yaml:"allowed_ips"`       // CIDR or bare IP
	AllowedRcptTo   []string `yaml:"allowed_rcpt_to"`   // exact-match
	AllowedFrom     []string `yaml:"allowed_from"`      // exact OR @domain suffix; empty = any
	MaxMessageBytes int      `yaml:"max_message_bytes"` // default 1048576 (1 MiB)
}

// TraceConfig controls the trace/capture feature - per-receiver raw-data
// dump to disk for debugging. Default disabled. Per-receiver toggles
// independent. When enabled, performance is impacted (synchronous writes).
//
// Files written 0600, directory 0700. Sensitive data (auth headers, alert
// details) WILL appear in trace files - operators should treat the output
// directory as containing secrets.
type TraceConfig struct {
	Enabled          bool                  `yaml:"enabled"`
	OutputDir        string                `yaml:"output_dir"`         // default /var/log/notrouter/trace
	ReminderInterval time.Duration         `yaml:"reminder_interval"`  // how often to log "trace is on"; default 1h
	Receivers        TraceReceiversConfig  `yaml:"receivers"`
}

// TraceReceiversConfig holds per-receiver trace toggles. Each block is
// independent - operators can trace SMTP without tracing syslog, etc.
type TraceReceiversConfig struct {
	SMTP      TraceSMTPConfig      `yaml:"smtp"`
	SyslogUDP TraceAppendConfig    `yaml:"syslog_udp"`
	SyslogTCP TraceAppendConfig    `yaml:"syslog_tcp"`
	Webhook   TraceAppendConfig    `yaml:"webhook"`
}

// TraceSMTPConfig - SMTP traces are one .eml file per message.
type TraceSMTPConfig struct {
	Enabled  bool `yaml:"enabled"`
	MaxFiles int  `yaml:"max_files"` // default 50; oldest deleted when exceeded
}

// TraceAppendConfig - append-mode JSONL traces (syslog, webhook).
type TraceAppendConfig struct {
	Enabled         bool  `yaml:"enabled"`
	MaxBytesPerFile int64 `yaml:"max_bytes_per_file"` // default 10 MiB
	MaxFiles        int   `yaml:"max_files"`          // default 3
}

// ParserConfig defines a single mail parser. Operators define one entry
// per vendor (CheckMK, Grafana, etc.). Parsers run in YAML order; first
// match wins. If no parser matches, the SMTP receiver falls back to the
// smtp_generic profile.
type ParserConfig struct {
	Name    string             `yaml:"name"`
	Match   ParserMatchConfig  `yaml:"match"`
	Profile string             `yaml:"profile"`
	Extract []ExtractorConfig  `yaml:"extract"`
}

// ParserMatchConfig holds the conditions under which a parser handles
// an event. Conditions AND together; an empty condition is ignored.
// At least one condition must be set or the parser would match every
// event (and shadow other parsers).
type ParserMatchConfig struct {
	SubjectPrefix  string `yaml:"subject_prefix,omitempty"`
	RcptToContains string `yaml:"rcpt_to_contains,omitempty"`
}

// ExtractorConfig is the polymorphic shape for parser extractors. The
// Type field discriminates; only the relevant fields are read for each
// type. Validation happens at parser-load time.
//
// Available types:
//   from_subject_regex       - regex on subject (Pattern)
//   from_attribute_regex     - regex on existing attr (Source, Pattern)
//   from_body_kvline         - "Label: value" line (Label, Attribute)
//   from_body_after_label    - everything after "Label:" (Label, Attribute)
//   from_header              - email header (Header, Attribute)
//   from_template            - Go template render (Template, Attribute)
//   dispatch_first_match     - try alternatives in order (Alternatives)
type ExtractorConfig struct {
	Type string `yaml:"type"`

	Label        string             `yaml:"label,omitempty"`
	Attribute    string             `yaml:"attribute,omitempty"`
	Pattern      string             `yaml:"pattern,omitempty"`
	Source       string             `yaml:"source,omitempty"`
	Template     string             `yaml:"template,omitempty"`
	Header       string             `yaml:"header,omitempty"`
	Alternatives []ExtractorConfig  `yaml:"alternatives,omitempty"`
}

type ProfileConfig struct {
	Entity     EntityConfig                  `yaml:"entity"`
	Normalize  NormalizeConfig               `yaml:"normalize"`
	Attributes map[string]AttributeExtractor `yaml:"attributes"`
}

type EntityConfig struct {
	FromJSON  string `yaml:"from_json"`
	FromRegex string `yaml:"from_regex"`
	FromField string `yaml:"from_field"`
}

type NormalizeConfig struct {
	Topic   string         `yaml:"topic"`
	Urgency UrgencyMapping `yaml:"urgency"`
}

type UrgencyMapping struct {
	FromJSON  string            `yaml:"from_json,omitempty"`
	FromField string            `yaml:"from_field,omitempty"`
	Map       map[string]string `yaml:"map"`
}

type AttributeExtractor struct {
	FromJSON       string `yaml:"from_json,omitempty"`
	FromField      string `yaml:"from_field,omitempty"`
	Static         string `yaml:"static,omitempty"`
	FromJSONString string `yaml:"from_json_string,omitempty"`
	Select         string `yaml:"select,omitempty"`
}

type DedupConfig struct {
	TTL       time.Duration `yaml:"ttl"`
	KeyFields []string      `yaml:"key_fields"`
}

type SuppressorConfig struct {
	Name   string      `yaml:"name"`
	Match  MatchConfig `yaml:"match"`
	Active *TimeWindow `yaml:"active,omitempty"`
}

type MatchConfig struct {
	EntityRegex string            `yaml:"entity_regex,omitempty"`
	EntityIPIn  []string          `yaml:"entity_ip_in,omitempty"`
	Topic       []string          `yaml:"topic,omitempty"`
	Urgency     []string          `yaml:"urgency,omitempty"`
	Attributes  map[string]string `yaml:"attributes,omitempty"`
}

type TimeWindow struct {
	From  time.Time `yaml:"from"`
	Until time.Time `yaml:"until"`
}

type LoggingConfig struct {
	Level                 string        `yaml:"level"`
	SuppressorLogThrottle time.Duration `yaml:"suppressor_log_throttle"`
}

type InstanceConfig struct {
	Type   string                 `yaml:"type"`
	Config map[string]interface{} `yaml:"config"`
	Retry  RetryConfig            `yaml:"retry,omitempty"`
}

type GroupConfig struct {
	Subscribers []string `yaml:"subscribers"`
}

type RoutingRuleConfig struct {
	Match  MatchConfig `yaml:"match"`
	Groups []string    `yaml:"groups"`
}

type DispatchConfig struct {
	GlobalDeliveryTTL time.Duration `yaml:"global_delivery_ttl"`
	DefaultRetry      RetryConfig   `yaml:"default_retry"`
}

type RetryConfig struct {
	Attempts int             `yaml:"attempts,omitempty"`
	Backoff  []time.Duration `yaml:"backoff,omitempty"`
}

type PipelineConfig struct {
	RawBufferSize      int `yaml:"raw_buffer_size"`
	NormalBufferSize   int `yaml:"normal_buffer_size"`
	InstanceBufferSize int `yaml:"instance_buffer_size"`
	ResolverWorkers    int `yaml:"resolver_workers"`
	NormalizerWorkers  int `yaml:"normalizer_workers"`
}

func Load(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read config: %w", err)
	}
	cfg := &Config{}
	dec := yaml.NewDecoder(bytes.NewReader(data))
	if os.Getenv("NOTROUTER_LAX_YAML") == "" {
		dec.KnownFields(true)
	}
	if err := dec.Decode(cfg); err != nil {
		return nil, fmt.Errorf("parse config (set NOTROUTER_LAX_YAML=1 to allow unknown fields): %w", err)
	}
	// Capture-and-clear the deprecated password BEFORE applyDefaults,
	// so applyDefaults can't accidentally set it to "admin" via the
	// previous behavior.
	cfg.deprecatedPassword = cfg.Auth.Admin.Password
	cfg.Auth.Admin.Password = ""

	cfg.applyDefaults()
	if err := cfg.validate(); err != nil {
		return nil, fmt.Errorf("validate config: %w", err)
	}
	cfg.path = path
	cfg.loadedHash = hashBytes(data)
	cfg.Links = filterLinks(cfg.Links)
	return cfg, nil
}

func hashBytes(b []byte) string {
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:8])
}

func HashFile(path string) (string, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	return hashBytes(b), nil
}

func (c *Config) applyDefaults() {
	if c.Listen.Webhook == "" {
		c.Listen.Webhook = ":8080"
	}
	if c.Listen.SyslogUDP == "" {
		c.Listen.SyslogUDP = ":5514"
	}
	if c.Listen.SyslogTCP == "" {
		c.Listen.SyslogTCP = ":5514"
	}
	if c.Listen.Admin == "" {
		c.Listen.Admin = ":9090"
	}
	if c.Auth.Admin.Username == "" {
		c.Auth.Admin.Username = "admin"
	}
	// NOTE: no more c.Auth.Admin.Password default. Auth lives in creds.json.
	if c.Auth.Admin.CredsPath == "" {
		c.Auth.Admin.CredsPath = "/var/lib/notrouter/creds.json"
	}
	if c.Auth.Admin.SessionTTL == 0 {
		c.Auth.Admin.SessionTTL = 2 * time.Hour
	}
	if c.Dedup.TTL == 0 {
		c.Dedup.TTL = 5 * time.Minute
	}
	if len(c.Dedup.KeyFields) == 0 {
		c.Dedup.KeyFields = []string{"entity", "topic"}
	}
	if c.Logging.Level == "" {
		c.Logging.Level = "info"
	}
	if c.Logging.SuppressorLogThrottle == 0 {
		c.Logging.SuppressorLogThrottle = 60 * time.Second
	}
	if c.Dispatch.GlobalDeliveryTTL == 0 {
		c.Dispatch.GlobalDeliveryTTL = 30 * time.Minute
	}
	if c.Dispatch.DefaultRetry.Attempts == 0 {
		c.Dispatch.DefaultRetry.Attempts = 3
	}
	if len(c.Dispatch.DefaultRetry.Backoff) == 0 {
		c.Dispatch.DefaultRetry.Backoff = []time.Duration{
			1 * time.Second,
			5 * time.Second,
			30 * time.Second,
		}
	}
	if c.Pipeline.RawBufferSize == 0 {
		c.Pipeline.RawBufferSize = 4096
	}
	if c.Pipeline.NormalBufferSize == 0 {
		c.Pipeline.NormalBufferSize = 2048
	}
	if c.Pipeline.InstanceBufferSize == 0 {
		c.Pipeline.InstanceBufferSize = 1024
	}
	if c.Pipeline.ResolverWorkers == 0 {
		c.Pipeline.ResolverWorkers = 4
	}
	if c.Pipeline.NormalizerWorkers == 0 {
		c.Pipeline.NormalizerWorkers = 4
	}
}

func (c *Config) validate() error {
	for name, inst := range c.PluginInstances {
		if inst.Type == "" {
			return fmt.Errorf("plugin instance %q has no type", name)
		}
	}
	for groupName, g := range c.Groups {
		for _, sub := range g.Subscribers {
			if _, ok := c.PluginInstances[sub]; !ok {
				return fmt.Errorf("group %q references unknown plugin instance %q", groupName, sub)
			}
		}
	}
	for i, rule := range c.Routing {
		for _, g := range rule.Groups {
			if _, ok := c.Groups[g]; !ok {
				return fmt.Errorf("routing rule %d references unknown group %q", i, g)
			}
		}
	}
	return nil
}

// filterLinks drops entries whose values are empty, whitespace-only, or
// one of the string sentinels ("false", "none", "off", "no") - case-
// insensitive.
func filterLinks(in map[string]string) map[string]string {
	if len(in) == 0 {
		return nil
	}
	out := make(map[string]string, len(in))
	for k, v := range in {
		trimmed := strings.TrimSpace(v)
		if trimmed == "" {
			continue
		}
		switch strings.ToLower(trimmed) {
		case "false", "no", "off", "none", "null", "nil", "disabled":
			continue
		}
		out[k] = trimmed
	}
	return out
}
