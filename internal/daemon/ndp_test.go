package daemon

import (
	"context"
	"net/netip"
	"os"
	"strings"
	"testing"

	"jailops.net/jailops/internal/ndproxy"
	"jailops.net/jailops/internal/priv"
	"jailops.net/jailops/sdk/api"
)

// fakeHost implements the two operations the proxy uses; everything else on priv.Host would panic if called.
type fakeHost struct {
	priv.Host
	openErr error
	answers []priv.NDPAnswerReq
}

func (h *fakeHost) NDPOpen(_ context.Context, uplink string, _ bool) (*os.File, error) {
	if h.openErr != nil {
		return nil, h.openErr
	}
	return os.Open(os.DevNull)
}
func (h *fakeHost) NDPAnswer(_ context.Context, q priv.NDPAnswerReq) error {
	h.answers = append(h.answers, q)
	return nil
}

func TestTheHelperRefusalReachesTheNetworkStatus(t *testing.T) {
	h := &fakeHost{openErr: api.Errorf(api.CodeForbidden, "prefix 2001:db8::/32 must be between /48 and /120")}
	_, err := newHelperNDP(h, nil, "vtnet0", nil)
	if !api.IsCode(err, api.CodeForbidden) || !strings.Contains(err.Error(), "must be between /48 and /120") {
		t.Fatalf("the refusal is lost: %v", err)
	}
}

// The injector hands the helper only what the advertisement says about whom and what; the helper builds its own frame.
func TestTheInjectorAsksTheHelperInsteadOfWritingAFrame(t *testing.T) {
	h := &fakeHost{}
	dev := &helperDevice{host: h, uplink: "vtnet0"}
	me := ndproxy.MAC{0xd6, 0xb8, 0x89, 0x47, 0x07, 0xd4}
	req := ndproxy.MAC{0x00, 0x00, 0x5e, 0x00, 0x02, 0x96}
	target := netip.MustParseAddr("2001:db8:1:2:100::10")
	frame := ndproxy.BuildNA(me, req, target, netip.MustParseAddr("fe80::1"), target, ndproxy.FlagSolicited|ndproxy.FlagOverride, &me)
	if err := dev.Send(frame); err != nil {
		t.Fatal(err)
	}
	if len(h.answers) != 1 || h.answers[0] != (priv.NDPAnswerReq{Uplink: "vtnet0", Target: target.String(), RequesterIP: "fe80::1", RequesterMAC: req.String()}) {
		t.Fatalf("%+v", h.answers)
	}
	// anything that is not an advertisement is not passed on
	ns := ndproxy.BuildNS(me, req, netip.MustParseAddr("fe80::1"), netip.MustParseAddr("ff02::1:ff00:10"), target, &me)
	if err := dev.Send(ns); err == nil || len(h.answers) != 1 {
		t.Fatal("a solicitation was passed to the helper")
	}
	if err := dev.Send([]byte("not a frame")); err == nil || len(h.answers) != 1 {
		t.Fatal("garbage was passed to the helper")
	}
}

// An unsolicited advertisement (to all nodes) is passed on as an announcement of the target, naming no requester; a
// unicast one to a neighbor stays an answer.
func TestTheInjectorMapsAnAnnouncementToTheAnnounceOperation(t *testing.T) {
	h := &fakeHost{}
	dev := &helperDevice{host: h, uplink: "vtnet0"}
	me := ndproxy.MAC{0xd6, 0xb8, 0x89, 0x47, 0x07, 0xd4}
	target := netip.MustParseAddr("2001:db8:1:2:100::10")
	all := netip.MustParseAddr("ff02::1")
	frame := ndproxy.BuildNA(me, ndproxy.MulticastMAC(all), target, all, target, ndproxy.FlagOverride, &me)
	if err := dev.Send(frame); err != nil {
		t.Fatal(err)
	}
	if len(h.answers) != 1 || h.answers[0] != (priv.NDPAnswerReq{Uplink: "vtnet0", Target: target.String(), Announce: true}) {
		t.Fatalf("%+v", h.answers)
	}
}
