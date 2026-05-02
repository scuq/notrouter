package source

import (
	"net"
	"net/http"
	"strings"
	"testing"
	"time"
)

func freeAddr(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := ln.Addr().String()
	ln.Close()
	return addr
}

func waitPost(t *testing.T, url, body, token string) *http.Response {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		req, _ := http.NewRequest(http.MethodPost, url, strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		if token != "" {
			req.Header.Set("Authorization", "Bearer "+token)
		}
		resp, err := http.DefaultClient.Do(req)
		if err == nil {
			return resp
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("post never succeeded")
	return nil
}

func TestHTTPSourceAcceptsEvent(t *testing.T) {
	addr := freeAddr(t)
	h := NewHTTP(addr)
	if err := h.Start(); err != nil {
		t.Fatal(err)
	}
	defer h.Close()

	resp := waitPost(t, "http://"+addr+"/notify", `{"topic":"alert.fire","message":"hello"}`, "")
	resp.Body.Close()
	if resp.StatusCode != http.StatusAccepted {
		t.Fatalf("status: %d", resp.StatusCode)
	}

	select {
	case ev := <-h.Events():
		if ev.Topic != "alert.fire" || ev.Message != "hello" {
			t.Fatalf("got %+v", ev)
		}
	case <-time.After(time.Second):
		t.Fatal("no event received")
	}
}

func TestHTTPSourceBearerAuth(t *testing.T) {
	addr := freeAddr(t)
	h := NewHTTP(addr, WithBearerToken("s3cret"))
	if err := h.Start(); err != nil {
		t.Fatal(err)
	}
	defer h.Close()

	resp := waitPost(t, "http://"+addr+"/notify", `{"topic":"a","message":"b"}`, "")
	resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", resp.StatusCode)
	}

	resp = waitPost(t, "http://"+addr+"/notify", `{"topic":"a","message":"b"}`, "s3cret")
	resp.Body.Close()
	if resp.StatusCode != http.StatusAccepted {
		t.Fatalf("expected 202, got %d", resp.StatusCode)
	}
}

func TestHTTPSourceAllowedTopics(t *testing.T) {
	addr := freeAddr(t)
	h := NewHTTP(addr, WithAllowedTopics([]string{"info.*", "audit.write"}))
	if err := h.Start(); err != nil {
		t.Fatal(err)
	}
	defer h.Close()

	cases := []struct {
		body       string
		wantStatus int
	}{
		{`{"topic":"info.boot","message":"x"}`, http.StatusAccepted},
		{`{"topic":"audit.write","message":"x"}`, http.StatusAccepted},
		{`{"topic":"alert.fire","message":"x"}`, http.StatusForbidden},
		{`{"topic":"random","message":"x"}`, http.StatusForbidden},
	}
	for _, c := range cases {
		resp := waitPost(t, "http://"+addr+"/notify", c.body, "")
		resp.Body.Close()
		if resp.StatusCode != c.wantStatus {
			t.Errorf("body=%s got=%d want=%d", c.body, resp.StatusCode, c.wantStatus)
		}
	}
}
