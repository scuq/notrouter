package config

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
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
	Links           map[string]string         `yaml:"links"`

	// path and loadedHash are populated by Load(). Not YAML-tagged so they
	// don't accidentally appear in re-marshaled output.
	path       string `yaml:"-"`
	loadedHash string `yaml:"-"`
}

// Path returns the file the config was loaded from. Used by the admin UI
// to re-read the file fresh from disk (the planned hot-reload path).
func (c *Config) Path() string { return c.path }

// LoadedHash is a short fingerprint of the bytes that were loaded. The
// admin UI compares this to a fresh hash of the disk file to flag drift
// between what's running and what's on disk.
func (c *Config) LoadedHash() string { return c.loadedHash }

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
	Username   string        `yaml:"username"`
	Password   string        `yaml:"password"`
	CredsPath  string        `yaml:"creds_path"`
	SessionTTL time.Duration `yaml:"session_ttl"`
}

type ReceiversConfig struct {
	Webhook WebhookReceiverConfig `yaml:"webhook"`
}

type WebhookReceiverConfig struct {
	Endpoints []WebhookEndpoint `yaml:"endpoints"`
}

type WebhookEndpoint struct {
	Path    string `yaml:"path"`
	Profile string `yaml:"profile"`
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
	FromJSON string            `yaml:"from_json"`
	Map      map[string]string `yaml:"map"`
}

type AttributeExtractor struct {
	FromJSON  string `yaml:"from_json,omitempty"`
	FromField string `yaml:"from_field,omitempty"`
	Static    string `yaml:"static,omitempty"`
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
	if err := yaml.Unmarshal(data, cfg); err != nil {
		return nil, fmt.Errorf("parse config: %w", err)
	}
	cfg.applyDefaults()
	if err := cfg.validate(); err != nil {
		return nil, fmt.Errorf("validate config: %w", err)
	}
	cfg.path = path
	cfg.loadedHash = hashBytes(data)
	return cfg, nil
}

// hashBytes returns the first 8 bytes of SHA256 hex-encoded. Plenty for
// drift detection; full hashes are wasteful in HTTP responses.
func hashBytes(b []byte) string {
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:8])
}

// HashFile is a public helper the admin handler uses to fingerprint
// what's on disk right now, so it can compare to LoadedHash() without
// opening the config package's internals.
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
	if c.Auth.Admin.Password == "" {
		c.Auth.Admin.Password = "admin"
	}
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
