package source

import (
	"strings"
	"testing"
	"time"
)

func TestStdinSourceParsesJSONLines(t *testing.T) {
	in := strings.NewReader(`{"topic":"a","message":"one"}
{"topic":"b","message":"two"}
not-json
{"message":"missing-topic"}
{"topic":"c","message":"three"}
`)
	s := NewStdin(StdinWithReader(in))
	if err := s.Start(); err != nil {
		t.Fatal(err)
	}
	defer s.Close()

	got := []string{}
	timeout := time.After(time.Second)
	for {
		select {
		case ev, ok := <-s.Events():
			if !ok {
				goto done
			}
			got = append(got, ev.Topic+":"+ev.Message)
		case <-timeout:
			t.Fatal("timeout")
		}
	}
done:
	want := []string{"a:one", "b:two", "c:three"}
	if len(got) != len(want) {
		t.Fatalf("got %v, want %v", got, want)
	}
	for i := range got {
		if got[i] != want[i] {
			t.Errorf("[%d] got %q want %q", i, got[i], want[i])
		}
	}
}
