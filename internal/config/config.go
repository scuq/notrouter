package config

import (
	"fmt"
	"os"

	"gopkg.in/yaml.v3"
)

type Config struct {
	Listen  string         `yaml:"listen"`
	Admin   AdminConfig    `yaml:"admin"`
	Sinks   []SinkConfig   `yaml:"sinks"`
	Routes  []RouteConfig  `yaml:"routes"`
	Sources []SourceConfig `yaml:"sources"`
}

type AdminConfig struct {
	Listen string `yaml:"listen"`
}

type SinkConfig struct {
	Name        string `yaml:"name"`
	Type        string `yaml:"type"`
	Path        string `yaml:"path,omitempty"`
	URL         string `yaml:"url,omitempty"`
	AuthToken   string `yaml:"auth_token,omitempty"`
	HMACSecret  string `yaml:"hmac_secret,omitempty"`
	HMACHeader  string `yaml:"hmac_header,omitempty"`
	Template    string `yaml:"template,omitempty"`
	ContentType string `yaml:"content_type,omitempty"`
	MaxRetries  int    `yaml:"max_retries,omitempty"`
	QueueSize   int    `yaml:"queue_size,omitempty"`

	// SMTP
	SMTPHost    string   `yaml:"smtp_host,omitempty"`
	SMTPPort    int      `yaml:"smtp_port,omitempty"`
	SMTPUser    string   `yaml:"smtp_user,omitempty"`
	SMTPPass    string   `yaml:"smtp_pass,omitempty"`
	From        string   `yaml:"from,omitempty"`
	To          []string `yaml:"to,omitempty"`
	Subject     string   `yaml:"subject,omitempty"`
	Body        string   `yaml:"body,omitempty"`
}

type RouteConfig struct {
	Topic       string   `yaml:"topic"`
	MinSeverity string   `yaml:"min_severity,omitempty"`
	DedupWindow string   `yaml:"dedup_window,omitempty"`
	RatePerSec  float64  `yaml:"rate_per_sec,omitempty"`
	RateBurst   int      `yaml:"rate_burst,omitempty"`
	GroupWindow string   `yaml:"group_window,omitempty"`
	GroupBy     string   `yaml:"group_by,omitempty"`
	Sinks       []string `yaml:"sinks"`
}

type SourceConfig struct {
	Name           string   `yaml:"name"`
	Type           string   `yaml:"type"`
	Listen         string   `yaml:"listen,omitempty"`
	BearerToken    string   `yaml:"bearer_token,omitempty"`
	TLSCert        string   `yaml:"tls_cert,omitempty"`
	TLSKey         string   `yaml:"tls_key,omitempty"`
	AllowedTopics  []string `yaml:"allowed_topics,omitempty"`
}

func Load(path string) (*Config, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return defaults(), nil
		}
		return nil, fmt.Errorf("read %s: %w", path, err)
	}

	cfg := &Config{}
	if err := yaml.Unmarshal(b, cfg); err != nil {
		return nil, fmt.Errorf("parse %s: %w", path, err)
	}
	if cfg.Listen == "" {
		cfg.Listen = ":8080"
	}
	if len(cfg.Sinks) == 0 {
		cfg.Sinks = defaults().Sinks
	}
	if err := cfg.Validate(); err != nil {
		return nil, fmt.Errorf("validate %s: %w", path, err)
	}
	return cfg, nil
}

func defaults() *Config {
	return &Config{
		Listen: ":8080",
		Sinks:  []SinkConfig{{Name: "stdout", Type: "stdout"}},
	}
}
