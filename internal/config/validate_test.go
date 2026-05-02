package config

import (
	"strings"
	"testing"
)

func TestValidateCatchesUnknownSink(t *testing.T) {
	cfg := &Config{
		Sinks:  []SinkConfig{{Name: "good", Type: "stdout"}},
		Routes: []RouteConfig{{Topic: "*", Sinks: []string{"missing"}}},
	}
	err := cfg.Validate()
	if err == nil || !strings.Contains(err.Error(), "missing") {
		t.Fatalf("want unknown-sink error, got %v", err)
	}
}

func TestValidateRejectsBadSeverity(t *testing.T) {
	cfg := &Config{
		Sinks:  []SinkConfig{{Name: "s", Type: "stdout"}},
		Routes: []RouteConfig{{Topic: "x", MinSeverity: "bogus", Sinks: []string{"s"}}},
	}
	if err := cfg.Validate(); err == nil {
		t.Fatal("want invalid severity error")
	}
}

func TestValidateAcceptsKnownSeverity(t *testing.T) {
	cfg := &Config{
		Sinks:  []SinkConfig{{Name: "s", Type: "stdout"}},
		Routes: []RouteConfig{{Topic: "x", MinSeverity: "warn", Sinks: []string{"s"}}},
	}
	if err := cfg.Validate(); err != nil {
		t.Fatalf("unexpected: %v", err)
	}
}

func TestValidateDuplicateSinkName(t *testing.T) {
	cfg := &Config{
		Sinks: []SinkConfig{
			{Name: "dup", Type: "stdout"},
			{Name: "dup", Type: "stdout"},
		},
	}
	if err := cfg.Validate(); err == nil {
		t.Fatal("want duplicate sink error")
	}
}

func TestSeverityAtLeast(t *testing.T) {
	cases := []struct {
		have, min string
		want      bool
	}{
		{"info", "warn", false},
		{"warn", "warn", true},
		{"error", "warn", true},
		{"info", "", true},
		{"", "info", false},
	}
	for _, c := range cases {
		if got := SeverityAtLeast(c.have, c.min); got != c.want {
			t.Errorf("SeverityAtLeast(%q,%q) = %v, want %v", c.have, c.min, got, c.want)
		}
	}
}
