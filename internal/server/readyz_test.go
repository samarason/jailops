package server_test

import (
	"context"
	"errors"
	"net/http"
	"slices"
	"sync/atomic"
	"testing"
	"time"

	"jailops.net/jailops/internal/auth"
	"jailops.net/jailops/internal/daemon"
	"jailops.net/jailops/internal/daemon/dtest"
	"jailops.net/jailops/internal/sys/zfs"
	"jailops.net/jailops/sdk/api"
)

// downZFS fails Exists, as a stopped helper does, while down is set.
type downZFS struct {
	zfs.Client
	down  atomic.Bool
	calls atomic.Int32
}

func (z *downZFS) Exists(ctx context.Context, name string) (bool, error) {
	z.calls.Add(1)
	if z.down.Load() {
		return false, errors.New("cannot reach jailops-priv: connection refused")
	}
	return z.Client.Exists(ctx, name)
}

func TestReadyzFollowsTheHelper(t *testing.T) {
	z := &downZFS{}
	clk := &stepClock{now: time.Now()}
	e := dtest.New(t, dtest.Options{Now: clk.Now, Clients: func(c *daemon.Clients) { z.Client = c.ZFS; c.ZFS = z }})
	code, body := rawDo(t, e, "GET", "/readyz", "", "", nil)
	if code != 200 || body != "ok\n" {
		t.Fatalf("healthy, anonymous: %d %q", code, body)
	}
	// a flood within the cache period is one helper call
	before := z.calls.Load()
	for i := 0; i < 50; i++ {
		rawDo(t, e, "GET", "/readyz", "", "", nil)
	}
	if n := z.calls.Load() - before; n != 0 {
		t.Errorf("%d helper calls for 50 probes within the cache period", n)
	}
	z.down.Store(true)
	clk.move(3 * time.Second)
	code, body = rawDo(t, e, "GET", "/readyz", "", "", nil)
	if code != 503 || body != "not ready: helper\n" {
		t.Errorf("helper down: %d %q (the error text must not leak)", code, body)
	}
	// liveness stays ok: the process answers
	if code, _ := rawDo(t, e, "GET", "/healthz", "", "", nil); code != 200 {
		t.Errorf("healthz with the helper down: %d", code)
	}
	z.down.Store(false)
	clk.move(3 * time.Second)
	if code, body = rawDo(t, e, "GET", "/readyz", "", "", nil); code != 200 {
		t.Errorf("helper back: %d %q", code, body)
	}
}

func TestReadyzIsPublicPlainAndLocal(t *testing.T) {
	e := dtest.New(t, dtest.Options{})
	// a route of the table, so the authorisation matrices run it for every identity
	if ent, ok := auth.DefaultRegistry().Lookup("GET", "/readyz"); !ok || !ent.Public || !slices.Contains(e.D.Server().RouteKeys(), "GET /readyz") {
		t.Fatal("GET /readyz is not a public route of the table")
	}
	req, _ := http.NewRequest("GET", e.HTTP.URL+"/readyz?host=elsewhere", nil)
	resp, err := leakClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	// ?host= is not forwarded, even on a hub: the probe answers for this daemon
	if resp.StatusCode != 200 {
		t.Errorf("?host=: %d", resp.StatusCode)
	}
	if ct := resp.Header.Get("Content-Type"); ct != "text/plain; charset=utf-8" {
		t.Errorf("content type %q", ct)
	}
	if cc := resp.Header.Get("Cache-Control"); cc != "no-store" {
		t.Errorf("cache control %q", cc)
	}
	// an anonymous local peer gets what an anonymous remote one gets
	for peer, cred := range ordinaryPeers {
		if code, body := serveAs(e, cred, "GET", "/readyz", "", ""); code != 200 || body != "ok\n" {
			t.Errorf("%s: %d %q", peer, code, body)
		}
	}
	// a token of any role gets the same answer
	if code, body := rawDo(t, e, "GET", "/readyz", e.Token(api.PermReadonly), "", nil); code != 200 || body != "ok\n" {
		t.Errorf("with a token: %d %q", code, body)
	}
}

// Anonymous routes have no request rate of their own; a bad credential counts toward the lockout of its source,
// and a locked-out source is refused on /readyz as on GET /api/v1.
func TestReadyzIsLimitedLikeOtherAnonymousRoutes(t *testing.T) {
	e := dtest.New(t, dtest.Options{Mutate: func(c *daemon.Config) { c.Limits.AuthFailureThreshold = 3 }})
	for i := 0; i < 5; i++ {
		rawDo(t, e, "GET", "/readyz", "jo_bad", "", nil)
	}
	for _, p := range []string{"/readyz", "/api/v1"} {
		if code, _ := rawDo(t, e, "GET", p, "jo_bad", "", nil); code != 429 {
			t.Errorf("%s from a locked-out source: %d, want 429", p, code)
		}
	}
}
