package sink

import (
	"net/smtp"
	"strings"
	"testing"

	"github.com/scuq/notrouter/internal/source"
)

func TestSMTPMessageBuild(t *testing.T) {
	ev := source.Event{Topic: "alert.fire", Message: "server on fire", Severity: "critical"}
	var (
		gotAddr string
		gotFrom string
		gotTo   []string
		gotMsg  []byte
	)
	send := func(addr string, _ smtp.Auth, from string, to []string, msg []byte) error {
		gotAddr, gotFrom, gotTo, gotMsg = addr, from, to, msg
		return nil
	}

	s, err := NewSMTP("smtp.example.com", 587,
		"alerts@example.com",
		[]string{"oncall@example.com", "backup@example.com"},
		SMTPWithAuth("user", "pass"),
		SMTPWithSubjectTemplate(`{{.Severity}}: {{.Topic}}`),
		SMTPWithBodyTemplate(`Topic: {{.Topic}}{{"\n"}}Message: {{.Message}}`),
		smtpWithSender(send),
	)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Deliver(ev); err != nil {
		t.Fatal(err)
	}
	if gotAddr != "smtp.example.com:587" {
		t.Errorf("addr = %q", gotAddr)
	}
	if gotFrom != "alerts@example.com" {
		t.Errorf("from = %q", gotFrom)
	}
	if len(gotTo) != 2 || gotTo[0] != "oncall@example.com" {
		t.Errorf("to = %v", gotTo)
	}
	got := string(gotMsg)
	for _, want := range []string{
		"From: alerts@example.com",
		"To: oncall@example.com, backup@example.com",
		"Subject: critical: alert.fire",
		"Topic: alert.fire",
		"Message: server on fire",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("missing %q in:\n%s", want, got)
		}
	}
}

func TestSMTPDefaultSubject(t *testing.T) {
	ev := source.Event{Topic: "info.boot", Severity: "info", Message: "ready"}
	if got := defaultSubject(ev); got != "[info] info.boot" {
		t.Errorf("got %q", got)
	}
	ev2 := source.Event{Topic: "topic-only", Message: "x"}
	if got := defaultSubject(ev2); got != "topic-only" {
		t.Errorf("got %q", got)
	}
}

func TestSMTPRequiresFields(t *testing.T) {
	_, err := NewSMTP("", 25, "a@b", []string{"c@d"})
	if err == nil {
		t.Fatal("expected host error")
	}
	_, err = NewSMTP("h", 25, "", []string{"c@d"})
	if err == nil {
		t.Fatal("expected from error")
	}
	_, err = NewSMTP("h", 25, "a@b", nil)
	if err == nil {
		t.Fatal("expected to error")
	}
}
