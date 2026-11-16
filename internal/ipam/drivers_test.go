package ipam

import "testing"

func TestDriverLikeName(t *testing.T) {
	for name, want := range map[string]string{
		"vmx0": "vmx", "em1": "em", "lo0": "lo", "bridge0": "bridge", "bridge": "bridge", "epair0a": "epair", "epair12b": "epair",
		"tap0": "tap", "wg0": "wg", "pflog0": "pflog", "vlan0.10": "vlan", "igb3": "igb", "vtnet0": "vtnet", "all": "all",
		"VMX0": "vmx", "ix0": "ix", "lagg0": "lagg", "tun9": "tun",
		// free names
		"office": "", "jo0": "", "jo7": "", "lan": "", "vmxnet": "", "em1x": "", "bridgeway": "", "epair0c": "", "lo0x": "",
		"vlan0.x": "", "vlan0.": "", "officega": "", "officegb": "", "jo1234567890aba": "", "": "", "0": "",
	} {
		got, ok := DriverLikeName(name)
		if got != want || ok != (want != "") {
			t.Errorf("%q: %q %v, want %q", name, got, ok, want)
		}
	}
}
