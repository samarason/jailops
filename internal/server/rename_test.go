package server_test

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"jailops.net/jailops/internal/daemon/dtest"
	"jailops.net/jailops/sdk/api"
)

// A rename over HTTP: the role of the route, the If-Match of the request, the event and the audit entry.
func TestRenameOverHTTP(t *testing.T) {
	e := dtest.New(t, dtest.Options{})
	e.Seed()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	g := e.Global()

	// a project administrator renames the objects of the project, not a network
	padmin := e.Scoped(api.PermAdmin, dtest.SeedProject)
	if _, err := padmin.Networks().Rename(ctx, "lan", api.Rename{NewName: "office"}, ""); !api.IsCode(err, api.CodeForbidden) {
		t.Fatalf("a project administrator renamed a network: %v", err)
	}
	if _, err := e.Client(api.PermOperator).Networks().Rename(ctx, "lan", api.Rename{NewName: "office"}, ""); !api.IsCode(err, api.CodeForbidden) {
		t.Fatalf("an operator renamed a network: %v", err)
	}
	// a strict body: a misspelled member is refused
	if code, body := e.Raw("POST", "/api/v1/networks/lan/rename", e.Token(api.PermAdmin), `{"newname":"x"}`); code != 400 || !strings.Contains(body, "newname") {
		t.Fatalf("%d %s", code, body)
	}
	_, etag, err := g.Networks().GetETag(ctx, "lan")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := g.Networks().Rename(ctx, "lan", api.Rename{NewName: "office"}, "41"); !api.IsCode(err, api.CodeConflict) {
		t.Fatalf("a stale If-Match: %v", err)
	}
	evs := e.Events(ctx, g)
	op, err := g.Networks().Rename(ctx, "lan", api.Rename{NewName: "office"}, etag)
	if err != nil {
		t.Fatal(err)
	}
	res, err := op.Wait(ctx)
	if err != nil || res.To != "office" {
		t.Fatalf("%+v %v", res, err)
	}
	for seen := false; !seen; {
		select {
		case ev := <-evs:
			var le api.LifecycleEvent
			if ev.Type == api.EventLifecycle && json.Unmarshal(ev.Metadata, &le) == nil && le.Action == "network-renamed" {
				if le.Source != "/api/v1/networks/office" {
					t.Fatalf("%+v", le)
				}
				seen = true
			}
		case <-ctx.Done():
			t.Fatal("no network-renamed event")
		}
	}
	code, body := e.Raw("GET", "/api/v1/audit", e.Token(api.PermAdmin), "")
	if code != 200 || !strings.Contains(body, "/api/v1/networks/lan/rename") || !strings.Contains(body, "rename network lan to office") {
		t.Fatalf("audit: %d %s", code, body)
	}
	// the project's jails see the network under its new name
	if _, err := padmin.Networks().Get(ctx, "office"); err != nil {
		t.Fatal(err)
	}
}
