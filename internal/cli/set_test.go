package cli_test

import (
	"strings"
	"testing"
)

// set changes only the attributes whose flags were given, and leaves the rest of the object alone.
func TestSetChangesOnlyTheGivenFlags(t *testing.T) {
	h := newHarness(t)
	h.seed()
	if out, errs, code := h.run("", "volume", "create", "data", "--uid", "5000", "--gid", "5000", "--mode", "0770", "--size", "10G"); code != 0 {
		t.Fatalf("volume create: %d %q %s", code, out, errs)
	}
	if out, errs, code := h.run("", "volume", "set", "data", "--size", "20G"); code != 0 {
		t.Fatalf("volume set: %d %q %s", code, out, errs)
	}
	out, errs, code := h.run("", "volume", "show", "data", "-o", "yaml")
	if code != 0 {
		t.Fatalf("volume show: %d %s", code, errs)
	}
	for _, want := range []string{"size: 20G", "uid: 5000", "gid: 5000", "mode: \"0770\""} {
		if !strings.Contains(out, want) {
			t.Errorf("after set --size the volume lacks %q:\n%s", want, out)
		}
	}
	if strings.Contains(out, "size: 10G") {
		t.Errorf("the old size is still there:\n%s", out)
	}
}

// A flag given with its own default value is a change too: a boolean can be turned off.
func TestSetCanTurnABooleanOff(t *testing.T) {
	h := newHarness(t)
	h.seed()
	if out, errs, code := h.run("", "network", "create", "dmz", "--ipv4", "10.61.0.1/24", "--uplink", "vtnet0", "--nat"); code != 0 {
		t.Fatalf("network create: %d %q %s", code, out, errs)
	}
	if out, _, _ := h.run("", "network", "show", "dmz", "-o", "yaml"); !strings.Contains(out, "nat: true") {
		t.Fatalf("the network has no NAT to turn off:\n%s", out)
	}
	if out, errs, code := h.run("", "network", "set", "dmz", "--nat=false"); code != 0 {
		t.Fatalf("network set --nat=false: %d %q %s", code, out, errs)
	}
	out, _, _ := h.run("", "network", "show", "dmz", "-o", "yaml")
	if strings.Contains(out, "nat: true") {
		t.Errorf("--nat=false did not turn NAT off:\n%s", out)
	}
	if !strings.Contains(out, "10.61.0.0/24") {
		t.Errorf("set lost the subnet:\n%s", out)
	}
}

func TestSetNeedsAFlagAndAKnownObject(t *testing.T) {
	h := newHarness(t)
	h.seed()
	if _, errs, code := h.run("", "volume", "set", "nope", "--size", "1G"); code == 0 || !strings.Contains(errs, "not found") {
		t.Errorf("an unknown volume: %d %s", code, errs)
	}
	h.run("", "volume", "create", "data")
	if _, errs, code := h.run("", "volume", "set", "data"); code != 2 || !strings.Contains(errs, "nothing to change") {
		t.Errorf("no flag: %d %s", code, errs)
	}
}
