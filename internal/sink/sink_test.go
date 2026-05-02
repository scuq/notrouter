package sink

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/scuq/notrouter/internal/config"
	"github.com/scuq/notrouter/internal/source"
)

func ev(msg string) source.Event {
	return source.Event{Topic: "t", Message: msg, Time: time.Unix(0, 0).UTC()}
}

func TestFileSinkAppends(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "out.log")
	s := NewFile(path)
	for _, m := range []string{"one", "two"} {
		if err := s.Deliver(ev(m)); err != nil {
			t.Fatalf("deliver: %v", err)
		}
	}
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if got := strings.TrimSpace(string(b)); got != "one\ntwo" {
		t.Fatalf("got %q", got)
	}
}

func TestBuildUnknownType(t *testing.T) {
	_, err := buildOne(config.SinkConfig{Name: "x", Type: "bogus"})
	if err == nil {
		t.Fatal("expected error for unknown sink type")
	}
}

func TestWebhookSinkPosts(t *testing.T) {
	var hits atomic.Int32
	var got string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		b, _ := io.ReadAll(r.Body)
		got = string(b)
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	s, _ := NewWebhook(srv.URL)
	if err := s.Deliver(source.Event{Topic: "alert.fire", Message: "hello", Time: time.Unix(0, 0).UTC()}); err != nil {
		t.Fatalf("deliver: %v", err)
	}
	if hits.Load() != 1 {
		t.Fatalf("hits = %d", hits.Load())
	}
	if !strings.Contains(got, `"topic":"alert.fire"`) || !strings.Contains(got, `"message":"hello"`) {
		t.Fatalf("body = %q", got)
	}
}

func TestWebhookSinkErrorsOnNon2xx(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "nope", http.StatusInternalServerError)
	}))
	defer srv.Close()

	s, _ := NewWebhook(srv.URL)
	if err := s.Deliver(ev("hi")); err == nil {
		t.Fatal("expected error on 500")
	}
}

func TestWebhookSinkRetriesUntilSuccess(t *testing.T) {
	var hits atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		if hits.Add(1) < 3 {
			http.Error(w, "nope", http.StatusInternalServerError)
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	s, err := NewWebhook(srv.URL, WithMaxRetries(3))
	if err != nil {
		t.Fatal(err)
	}
	s.sleep = func(time.Duration) {}
	if err := s.Deliver(ev("hi")); err != nil {
		t.Fatalf("expected success after retries: %v", err)
	}
	if hits.Load() != 3 {
		t.Fatalf("hits = %d, want 3", hits.Load())
	}
}

func TestWebhookSinkSendsTemplateAndAuth(t *testing.T) {
	var gotAuth, gotBody, gotCT string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Authorization")
		gotCT = r.Header.Get("Content-Type")
		b, _ := io.ReadAll(r.Body)
		gotBody = string(b)
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	tmpl := `{"text":"[{{.Severity}}] {{.Topic}}: {{.Message}}"}`
	s, err := NewWebhook(srv.URL,
		WithTemplate(tmpl),
		WithAuthToken("tok"),
		WithContentType("application/json"),
	)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Deliver(source.Event{Topic: "alert.fire", Message: "FIRE", Severity: "critical"}); err != nil {
		t.Fatal(err)
	}
	if gotAuth != "Bearer tok" {
		t.Errorf("auth = %q", gotAuth)
	}
	if gotCT != "application/json" {
		t.Errorf("content-type = %q", gotCT)
	}
	want := `{"text":"[critical] alert.fire: FIRE"}`
	if gotBody != want {
		t.Errorf("body = %q, want %q", gotBody, want)
	}
}

func TestWebhookSinkRejectsBadTemplate(t *testing.T) {
	_, err := NewWebhook("http://x", WithTemplate("{{.Topic"))
	if err == nil {
		t.Fatal("expected template parse error")
	}
}

func TestWebhookSinkSignsWithHMAC(t *testing.T) {
	var gotSig, gotBody string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotSig = r.Header.Get("X-Hub-Signature-256")
		b, _ := io.ReadAll(r.Body)
		gotBody = string(b)
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	s, err := NewWebhook(srv.URL,
		WithHMAC("topsecret", "X-Hub-Signature-256"),
		WithTemplate(`{"m":"{{.Message}}"}`),
	)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Deliver(source.Event{Topic: "t", Message: "hi"}); err != nil {
		t.Fatal(err)
	}

	mac := hmacSHA256([]byte("topsecret"), []byte(gotBody))
	want := "sha256=" + mac
	if gotSig != want {
		t.Fatalf("sig = %q, want %q", gotSig, want)
	}
}

func hmacSHA256(key, msg []byte) string {
	mac := hmac.New(sha256.New, key)
	mac.Write(msg)
	return hex.EncodeToString(mac.Sum(nil))
}

func TestWebhookSinkExhaustsRetries(t *testing.T) {
	var hits atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		hits.Add(1)
		http.Error(w, "nope", http.StatusInternalServerError)
	}))
	defer srv.Close()

	s, err := NewWebhook(srv.URL, WithMaxRetries(2))
	if err != nil {
		t.Fatal(err)
	}
	s.sleep = func(time.Duration) {}
	if err := s.Deliver(ev("hi")); err == nil {
		t.Fatal("expected error after exhausting retries")
	}
	if hits.Load() != 3 {
		t.Fatalf("hits = %d, want 3 (initial + 2 retries)", hits.Load())
	}
}
