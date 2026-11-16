package server_test

import (
	"context"
	"encoding/json"
	"net"
	"path/filepath"
	"testing"
	"time"

	"jailops.net/jailops/internal/daemon"
	"jailops.net/jailops/internal/daemon/dtest"
	"jailops.net/jailops/sdk/api"
)

func devdCheck(t *testing.T, e *dtest.Env) (api.DoctorCheck, bool) {
	t.Helper()
	rep, err := e.Admin.Doctor(ctxT(t))
	if err != nil {
		t.Fatal(err)
	}
	for _, ch := range rep.Checks {
		if ch.Name == "host.devd" {
			return ch, true
		}
	}
	return api.DoctorCheck{}, false
}

// The kernel's notifications of devd become events: a link change of the uplink, a ZFS error, a limit a jail hit;
// what JailOps does not own, and what it does not know, is left out.
func TestDevdNotificationsBecomeEvents(t *testing.T) {
	path := filepath.Join(t.TempDir(), "devd.pipe")
	ln, err := net.ListenUnix("unixpacket", &net.UnixAddr{Name: path, Net: "unixpacket"})
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	accepted := make(chan *net.UnixConn, 1)
	go func() {
		if c, err := ln.AcceptUnix(); err == nil {
			accepted <- c
		}
	}()
	on := true
	e := dtest.New(t, dtest.Options{Mutate: func(c *daemon.Config) { c.Devd.Enable, c.Devd.Pipe = &on, path }})
	e.Seed()
	mustJail(t, e, "web")
	lan, err := e.Admin.Networks().Patch(ctxT(t), "lan", map[string]any{"spec": map[string]any{"uplink": "em0"}}, "")
	if err != nil || lan.Spec.Uplink != "em0" {
		t.Fatalf("%v %+v", err, lan.Spec)
	}
	var conn *net.UnixConn
	select {
	case conn = <-accepted:
	case <-time.After(10 * time.Second):
		t.Fatal("the daemon did not connect to the socket")
	}
	defer conn.Close()
	deadline := time.Now().Add(10 * time.Second)
	for {
		if ch, ok := devdCheck(t, e); ok && ch.Status == api.DoctorOK {
			break
		}
		if time.Now().After(deadline) {
			ch, _ := devdCheck(t, e)
			t.Fatalf("doctor: %+v", ch)
		}
		time.Sleep(20 * time.Millisecond)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	sub := e.D.Service().Events().Subscribe(ctx, -1)
	for _, rec := range []string{
		"!system=IFNET subsystem=wlan0 type=LINK_DOWN",                                     // not JailOps's
		"!system=JAILOPS subsystem=test type=ping",                                         // unknown
		"!system=RCTL subsystem=rule type=matched rule=jail:alpha_nobody:maxproc:devctl=1", // not a jail of this host
		"!system=IFNET subsystem=" + lan.Spec.Uplink + " type=LINK_DOWN",
		"!system=ZFS subsystem=ZFS type=ereport.fs.zfs.checksum pool=tank vdev_path=/dev/da0",
		"!system=RCTL subsystem=rule type=matched rule=jail:alpha_web:memoryuse:devctl=1073741824 jail=alpha_web",
	} {
		if _, err := conn.Write([]byte(rec + "\n")); err != nil { // devd ends every record with a newline
			t.Fatal(err)
		}
	}
	got := map[string]api.LifecycleEvent{}
	for len(got) < 3 {
		select {
		case se, ok := <-sub:
			if !ok {
				t.Fatalf("the event stream ended with %v", got)
			}
			var le api.LifecycleEvent
			if se.Event.Type != api.EventLifecycle || json.Unmarshal(se.Event.Metadata, &le) != nil || le.Requestor != "devd" {
				continue
			}
			got[le.Action] = le
		case <-ctx.Done():
			t.Fatalf("events so far: %+v", got)
		}
	}
	if le := got["host-link-down"]; le.Source != "/api/v1/host" || le.Project != "" || le.Detail == "" {
		t.Errorf("%+v", le)
	}
	if le := got["host-zfs-error"]; le.Source != "/api/v1/host" || le.Detail != "pool tank: checksum on /dev/da0" {
		t.Errorf("%+v", le)
	}
	if le := got["jail-limit-hit"]; le.Source != "/api/v1/jails/web" || le.Project != "alpha" || le.Detail == "" {
		t.Errorf("%+v", le)
	}
	// nothing else arrives: the three records JailOps does not care about made no event
	select {
	case se := <-sub:
		var le api.LifecycleEvent
		if json.Unmarshal(se.Event.Metadata, &le) == nil && le.Requestor == "devd" {
			t.Errorf("an uninteresting record became an event: %+v", le)
		}
	case <-time.After(300 * time.Millisecond):
	}
}

// A host without devd (or a socket the daemon cannot read) never breaks the daemon: doctor warns and says why.
func TestDevdMissingSocketIsAWarning(t *testing.T) {
	on := true
	e := dtest.New(t, dtest.Options{Mutate: func(c *daemon.Config) {
		c.Devd.Enable, c.Devd.Pipe = &on, filepath.Join(t.TempDir(), "no-such-devd.pipe")
	}})
	e.Seed()
	deadline := time.Now().Add(10 * time.Second)
	for {
		if ch, ok := devdCheck(t, e); ok {
			if ch.Status != api.DoctorWarn || ch.Message == "" || ch.Hint == "" {
				t.Fatalf("%+v", ch)
			}
			return
		}
		if time.Now().After(deadline) {
			t.Fatal("doctor has no host.devd check")
		}
		time.Sleep(20 * time.Millisecond)
	}
}

// Where nothing asks for it (every platform but FreeBSD by default, or devd.enable false) doctor has no such check.
func TestDevdOffHasNoCheck(t *testing.T) {
	off := false
	e := dtest.New(t, dtest.Options{Mutate: func(c *daemon.Config) { c.Devd.Enable = &off }})
	e.Seed()
	if ch, ok := devdCheck(t, e); ok {
		t.Fatalf("%+v", ch)
	}
}
