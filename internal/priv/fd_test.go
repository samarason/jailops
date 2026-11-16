package priv

import (
	"context"
	"io"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"jailops.net/jailops/sdk/api"
)

// fakeNDP is an NDPDevice that records what was asked of it. Capture hands out a descriptor of an ordinary file.
type fakeNDP struct {
	mu       sync.Mutex
	file     string
	captured []string
	sent     [][]byte
	hw       [6]byte
	local    []string
	sendErr  error
	// routes are the host routes the table has: address to interface.
	routes map[string]string
}

func newFakeNDP(dir string) *fakeNDP {
	f := &fakeNDP{file: filepath.Join(dir, "device"), hw: [6]byte{0xd6, 0xb8, 0x89, 0x47, 0x07, 0xd4},
		routes: map[string]string{"2001:db8:1:2:100::10": "jo30gb"}}
	_ = os.WriteFile(f.file, []byte("pretend capture"), 0o600)
	return f
}

func (f *fakeNDP) Capture(uplink string, promisc bool) (*os.File, error) {
	f.mu.Lock()
	f.captured = append(f.captured, uplink)
	f.mu.Unlock()
	return os.Open(f.file)
}
func (f *fakeNDP) Send(uplink string, frame []byte) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.sendErr != nil {
		return f.sendErr
	}
	f.sent = append(f.sent, append([]byte(nil), frame...))
	return nil
}
func (f *fakeNDP) HardwareAddr(string) ([6]byte, error) { return f.hw, nil }
func (f *fakeNDP) LocalAddrs() ([]netip.Addr, error) {
	var out []netip.Addr
	for _, s := range f.local {
		out = append(out, netip.MustParseAddr(s))
	}
	return out, nil
}
func (f *fakeNDP) HostRoutes() (map[netip.Addr]string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := map[netip.Addr]string{}
	for a, i := range f.routes {
		out[netip.MustParseAddr(a)] = i
	}
	return out, nil
}
func (f *fakeNDP) captures() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string(nil), f.captured...)
}
func (f *fakeNDP) frames() int { f.mu.Lock(); defer f.mu.Unlock(); return len(f.sent) }

// TestNDPOpenPassesADescriptor sends a descriptor over the socket with SCM_RIGHTS, the mechanism the helper uses to
// hand the daemon its capture of the uplink. UNVERIFIED here: what is opened on FreeBSD is /dev/bpf (checked on a host).
func TestNDPOpenPassesADescriptor(t *testing.T) {
	e := newEnv(t)
	f := e.serve(t, selfPeers())
	c, err := Dial(f.sock)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	ctx := context.Background()
	dev := e.local.d.NDP.(*fakeNDP)

	for i := 0; i < 3; i++ { // several in a row exercise the descriptor queue
		fl, err := c.NDPOpen(ctx, "em0", false)
		if err != nil {
			t.Fatal(err)
		}
		b, err := io.ReadAll(fl)
		fl.Close()
		if err != nil || string(b) != "pretend capture" {
			t.Fatalf("read through the passed descriptor: %q %v", b, err)
		}
	}
	if got := dev.captures(); len(got) != 3 || got[0] != "em0" {
		t.Errorf("captured %v", got)
	}
	// An uplink the operator did not approve gets nothing, and the device is never opened for it.
	if _, err := c.NDPOpen(ctx, "igb0", false); !api.IsCode(err, api.CodeForbidden) || !strings.Contains(err.Error(), "no network in IPv6 proxy mode uses") {
		t.Errorf("an uplink outside the approval: %v", err)
	}
	if len(dev.captures()) != 3 {
		t.Error("the device was opened for a refused request")
	}
	// interleaved with ordinary traffic and from many goroutines
	done := make(chan error, 8)
	for i := 0; i < 8; i++ {
		go func(i int) {
			if i%2 == 0 {
				fl, err := c.NDPOpen(ctx, "em0", false)
				if err == nil {
					fl.Close()
				}
				done <- err
				return
			}
			_, err := c.ZFS().Exists(ctx, "tank/jailops")
			done <- err
		}(i)
	}
	for i := 0; i < 8; i++ {
		if err := <-done; err != nil && !api.IsCode(err, api.CodeBusy) {
			t.Error(err)
		}
	}
	// no descriptors are leaked by the server for unsupported requests
	e2 := newEnv(t)
	l2, _ := NewLocal(e2.cfg, Deps{ZFS: e2.zfs}, WithoutChown())
	e2.local = l2
	f2 := e2.serve(t, selfPeers())
	c2, _ := Dial(f2.sock)
	defer c2.Close()
	if _, err := c2.NDPOpen(ctx, "em0", false); !api.IsCode(err, api.CodeUnsupported) {
		t.Errorf("no capture support: %v", err)
	}
}
