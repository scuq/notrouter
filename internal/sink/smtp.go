package sink

import (
	"bytes"
	"errors"
	"fmt"
	"net/smtp"
	"strings"
	"text/template"
	"time"

	"github.com/scuq/notrouter/internal/source"
)

// SMTPSender abstracts net/smtp.SendMail for testability.
type SMTPSender func(addr string, a smtp.Auth, from string, to []string, msg []byte) error

type SMTP struct {
	host        string
	port        int
	username    string
	password    string
	from        string
	to          []string
	subjectTmpl *template.Template
	bodyTmpl    *template.Template
	send        SMTPSender
}

type SMTPOption func(*SMTP) error

func SMTPWithAuth(user, pass string) SMTPOption {
	return func(s *SMTP) error { s.username = user; s.password = pass; return nil }
}

func SMTPWithSubjectTemplate(tmpl string) SMTPOption {
	return func(s *SMTP) error {
		if tmpl == "" {
			return nil
		}
		t, err := template.New("subject").Parse(tmpl)
		if err != nil {
			return fmt.Errorf("subject template: %w", err)
		}
		s.subjectTmpl = t
		return nil
	}
}

func SMTPWithBodyTemplate(tmpl string) SMTPOption {
	return func(s *SMTP) error {
		if tmpl == "" {
			return nil
		}
		t, err := template.New("body").Parse(tmpl)
		if err != nil {
			return fmt.Errorf("body template: %w", err)
		}
		s.bodyTmpl = t
		return nil
	}
}

func smtpWithSender(send SMTPSender) SMTPOption {
	return func(s *SMTP) error { s.send = send; return nil }
}

func NewSMTP(host string, port int, from string, to []string, opts ...SMTPOption) (*SMTP, error) {
	if host == "" {
		return nil, errors.New("smtp host required")
	}
	if port == 0 {
		port = 25
	}
	if from == "" {
		return nil, errors.New("smtp from required")
	}
	if len(to) == 0 {
		return nil, errors.New("smtp to required")
	}
	s := &SMTP{
		host: host, port: port,
		from: from, to: to,
		send: smtp.SendMail,
	}
	for _, opt := range opts {
		if err := opt(s); err != nil {
			return nil, err
		}
	}
	return s, nil
}

func (s *SMTP) Deliver(ev source.Event) error {
	subject, err := renderTmpl(s.subjectTmpl, ev, defaultSubject(ev))
	if err != nil {
		return err
	}
	body, err := renderTmpl(s.bodyTmpl, ev, ev.Message)
	if err != nil {
		return err
	}

	msg := buildMessage(s.from, s.to, subject, body, time.Now().UTC())
	addr := fmt.Sprintf("%s:%d", s.host, s.port)

	var auth smtp.Auth
	if s.username != "" {
		auth = smtp.PlainAuth("", s.username, s.password, s.host)
	}
	return s.send(addr, auth, s.from, s.to, msg)
}

func renderTmpl(t *template.Template, ev source.Event, fallback string) (string, error) {
	if t == nil {
		return fallback, nil
	}
	var buf bytes.Buffer
	if err := t.Execute(&buf, ev); err != nil {
		return "", err
	}
	return buf.String(), nil
}

func defaultSubject(ev source.Event) string {
	if ev.Severity != "" {
		return fmt.Sprintf("[%s] %s", ev.Severity, ev.Topic)
	}
	return ev.Topic
}

func buildMessage(from string, to []string, subject, body string, now time.Time) []byte {
	var buf bytes.Buffer
	fmt.Fprintf(&buf, "From: %s\r\n", from)
	fmt.Fprintf(&buf, "To: %s\r\n", strings.Join(to, ", "))
	fmt.Fprintf(&buf, "Subject: %s\r\n", subject)
	fmt.Fprintf(&buf, "Date: %s\r\n", now.Format(time.RFC1123Z))
	fmt.Fprintf(&buf, "MIME-Version: 1.0\r\n")
	fmt.Fprintf(&buf, "Content-Type: text/plain; charset=utf-8\r\n")
	fmt.Fprintf(&buf, "\r\n")
	buf.WriteString(body)
	return buf.Bytes()
}
