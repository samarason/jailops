package server_test

import (
	"bufio"
	"context"
	"encoding/json"
	"net/http"
	"strconv"
	"strings"
	"testing"
	"time"

	"jailops.net/jailops/internal/daemon/dtest"
	"jailops.net/jailops/sdk"
	"jailops.net/jailops/sdk/api"
)

func TestEventsStreamAndFilter(t *testing.T) {
	e := seeded(t)
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	got := e.Events(ctx, e.Admin, sdk.Types(api.EventLifecycle))
	mustJail(t, e, "web")
	want := map[string]bool{"jail-created": false}
	deadline := time.After(10 * time.Second)
	for !want["jail-created"] {
		select {
		case ev := <-got:
			if ev.Type != api.EventLifecycle {
				t.Fatalf("filter let %s through", ev.Type)
			}
			var le api.LifecycleEvent
			_ = json.Unmarshal(ev.Metadata, &le)
			if le.Action == "jail-created" && le.Source == "/api/v1/jails/web" {
				want["jail-created"] = true
				if le.Requestor == "" || ev.Host != e.D.Service().HostUUID() {
					t.Fatalf("%+v %+v", le, ev)
				}
			}
		case <-deadline:
			t.Fatal("no jail-created event")
		}
	}
}

// A client that reconnects with Last-Event-ID gets what it missed, in order,
// without duplicates, then live events.
func TestEventsReplayFromLastEventID(t *testing.T) {
	e := seeded(t)
	tok := e.Token(api.PermAdmin)
	// newest is the id of the newest lifecycle event: a replay has brought everything retained once it arrives.
	newest := func() int64 {
		var last int64
		for after := int64(0); ; {
			evs, err := e.D.Service().DB().Events.Since(context.Background(), after, 1000)
			if err != nil || len(evs) == 0 {
				return last
			}
			for _, se := range evs {
				if se.Event.Type == api.EventLifecycle {
					last = se.ID
				}
			}
			after = evs[len(evs)-1].ID
		}
	}
	// read streams lifecycle events after last until n of them arrived or the one with id until did.
	read := func(last string, n int, until int64) ([]int64, []string) {
		req, _ := http.NewRequest("GET", e.HTTP.URL+"/api/v1/events?type=lifecycle", nil)
		req.Header.Set("Authorization", "Bearer "+tok)
		if last != "" {
			req.Header.Set("Last-Event-ID", last)
		}
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		resp, err := http.DefaultClient.Do(req.WithContext(ctx))
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		if ct := resp.Header.Get("Content-Type"); ct != "text/event-stream" {
			t.Fatalf("%s", ct)
		}
		var ids []int64
		var actions []string
		sc := bufio.NewScanner(resp.Body)
		sawRetry := false
		for sc.Scan() && len(ids) < n && (until == 0 || len(ids) == 0 || ids[len(ids)-1] < until) {
			l := sc.Text()
			switch {
			case strings.HasPrefix(l, "retry:"):
				sawRetry = true
			case strings.HasPrefix(l, "id: "):
				id, _ := strconv.ParseInt(l[4:], 10, 64)
				ids = append(ids, id)
			case strings.HasPrefix(l, "data: "):
				var ev api.Event
				_ = json.Unmarshal([]byte(l[6:]), &ev)
				var le api.LifecycleEvent
				_ = json.Unmarshal(ev.Metadata, &le)
				actions = append(actions, le.Action)
			}
		}
		if !sawRetry {
			t.Error("no retry field")
		}
		return ids, actions
	}
	mustJail(t, e, "a")
	first, _ := read("0", 3, 0) // everything retained: image and network and jail events
	if len(first) < 3 {
		t.Fatalf("%v", first)
	}
	mustJail(t, e, "b")
	ids, actions := read(strconv.FormatInt(first[0], 10), 1000, newest())
	_ = actions
	if len(ids) == 0 {
		t.Fatal("nothing replayed")
	}
	for i, id := range ids {
		if id <= first[0] {
			t.Fatalf("replayed an old event: %v", ids)
		}
		if i > 0 && id != ids[i-1]+1 {
			// lifecycle-only filtering may skip operation ids but must stay increasing
			if id <= ids[i-1] {
				t.Fatalf("not increasing: %v", ids)
			}
		}
	}
	if !contains(actions, "jail-created") {
		t.Fatalf("%v", actions)
	}
	// Starting at the newest event shows nothing old.
	done := make(chan []int64, 1)
	now := strconv.FormatInt(e.D.Service().Events().Last(), 10)
	go func() { i, _ := read(now, 1, 0); done <- i }()
	mustJail(t, e, "c")
	select {
	case i := <-done:
		if len(i) != 1 || i[0] <= ids[len(ids)-1] {
			t.Fatalf("%v after %v", i, ids)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("no live event")
	}
}

func contains(l []string, s string) bool {
	for _, x := range l {
		if x == s {
			return true
		}
	}
	return false
}

func TestEventsBadRequests(t *testing.T) {
	e := dtest.New(t, dtest.Options{})
	tok := e.Token(api.PermReadonly)
	if code, _ := e.Raw("GET", "/api/v1/events?type=bogus", tok, ""); code != 400 {
		t.Fatalf("%d", code)
	}
	if code, _ := e.RawHdr("GET", "/api/v1/events", tok, "", map[string]string{"Last-Event-ID": "abc"}); code != 400 {
		t.Fatalf("%d", code)
	}
	// A token in the query string authenticates nothing, the event stream included: it would end up in logs and
	// browser histories.
	for _, p := range []string{"/api/v1/events", "/api/v1/operations"} {
		if code, _ := e.Raw("GET", p+"?access_token="+tok, "", ""); code != 401 {
			t.Fatalf("a token in the query authenticated %s: %d", p, code)
		}
	}
}
