package server_test

import (
	"context"
	"net/http"
	"testing"
	"time"

	"jailops.net/jailops/internal/daemon/dtest"
	"jailops.net/jailops/sdk/api"
)

// One identity holds at most 16 event streams; the next is rate_limited, and a closed stream frees its slot.
func TestEventStreamsPerIdentityAreBounded(t *testing.T) {
	e := dtest.New(t, dtest.Options{})
	tok := e.IdentityToken(api.PermReadonly, true)
	other := e.IdentityToken(api.PermReadonly, true)
	cl := &http.Client{Transport: &http.Transport{MaxIdleConnsPerHost: 64}}
	t.Cleanup(cl.CloseIdleConnections)
	open := func(token string) (int, context.CancelFunc) {
		ctx, cancel := context.WithCancel(context.Background())
		req, _ := http.NewRequestWithContext(ctx, "GET", e.HTTP.URL+"/api/v1/events", nil)
		req.Header.Set("Authorization", "Bearer "+token)
		resp, err := cl.Do(req)
		if err != nil {
			cancel()
			t.Fatal(err)
		}
		if resp.StatusCode != 200 {
			resp.Body.Close()
		}
		t.Cleanup(cancel)
		return resp.StatusCode, func() { cancel(); resp.Body.Close() }
	}
	var closers []context.CancelFunc
	for i := range 16 {
		code, c := open(tok)
		if code != 200 {
			t.Fatalf("stream %d: %d", i+1, code)
		}
		closers = append(closers, c)
	}
	if code, _ := open(tok); code != 429 {
		t.Fatalf("stream 17: %d", code)
	}
	if code, _ := open(other); code != 200 {
		t.Fatalf("another identity: %d", code)
	}
	closers[0]()
	for i := 0; ; i++ {
		code, _ := open(tok)
		if code == 200 {
			break
		}
		if i == 300 {
			t.Fatalf("a closed stream did not free its slot: %d", code)
		}
		time.Sleep(10 * time.Millisecond) // the server sees the closed connection
	}
}
