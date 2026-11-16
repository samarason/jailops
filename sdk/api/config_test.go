package api

import (
	"reflect"
	"strings"
	"testing"
)

func TestRegistryIsConsistent(t *testing.T) {
	seen := map[string]bool{}
	for _, k := range ConfigKeys() {
		if k.Name == "" || k.Description == "" || k.Type == "" || k.Path == "" || seen[k.Name] {
			t.Errorf("bad entry %+v", k)
		}
		seen[k.Name] = true
		if k.Type == "enum" && len(k.Values) == 0 {
			t.Errorf("%s: an enum without values", k.Name)
		}
	}
	for _, want := range []string{"limits.memory", "limits.cpu", "limits.pids", "boot.autostart", "boot.priority", "boot.depends", "image", "hostname",
		"update.strategy", "update.window", "firewall.policies", "nic.<device>.mtu", "nic.<device>.network", "devfs.<name>.device", "proxy.<name>.listen", "env.<var>", "profiles"} {
		if !seen[want] {
			t.Errorf("missing key %s", want)
		}
	}
	// A returned slice is a copy.
	ConfigKeys()[0].Name = "x"
	if ConfigKeys()[0].Name == "x" {
		t.Fatal("the registry was modified through its listing")
	}
}

func TestApplyConfigSetsAndReportsRestarts(t *testing.T) {
	s := JailSpec{Image: "fb@stable"}
	restart, err := ApplyConfig(&s, map[string]string{
		"limits.memory": "2G", "limits.cpu": "2", "boot.autostart": "true", "boot.depends": "db, cache",
		"nic.eth0.network": "lan", "nic.eth0.ipv4": "auto", "nic.eth0.mtu": "1400", "nic.eth1.network": "dmz",
		"disk.data.mount": "/var/db", "disk.data.read_only": "yes",
		"devfs.t.device": "tun", "proxy.web.listen": ":8080", "proxy.web.jail_port": "80", "env.TZ": "UTC",
		"firewall.policies": "web, ssh-office", "update.strategy": "rebase",
	}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if s.Resources.Memory != "2G" || s.Resources.CPU != 2 || !s.Boot.Autostart || !reflect.DeepEqual(s.Boot.Depends, []string{"db", "cache"}) {
		t.Fatalf("%+v", s)
	}
	if !reflect.DeepEqual(s.Firewall.Policies, []string{"web", "ssh-office"}) {
		t.Fatalf("%+v", s.Firewall)
	}
	if len(s.Network) != 2 || s.Network[0].Name != "eth0" || s.Network[0].MTU != 1400 || s.Network[1].Name != "eth1" || s.Network[1].Network != "dmz" {
		t.Fatalf("%+v", s.Network)
	}
	if len(s.Volumes) != 1 || !s.Volumes[0].ReadOnly || s.Volumes[0].Mount != "/var/db" {
		t.Fatalf("%+v", s.Volumes)
	}
	if len(s.Devfs) != 1 || s.Devfs[0].Device != "tun" || len(s.Proxy) != 1 || s.Proxy[0].JailPort != 80 || s.Env["TZ"] != "UTC" {
		t.Fatalf("%+v", s)
	}
	// Boot and firewall changes are live; limits, devices and environment need a restart.
	want := []string{"devfs.t.device", "disk.data.mount", "disk.data.read_only", "env.TZ", "limits.cpu", "limits.memory",
		"nic.eth0.ipv4", "nic.eth0.mtu", "nic.eth0.network", "nic.eth1.network"}
	if !reflect.DeepEqual(restart, want) {
		t.Fatalf("restart:\n got %v\nwant %v", restart, want)
	}
	// Setting the same value again changes nothing and needs no restart.
	restart, err = ApplyConfig(&s, map[string]string{"limits.memory": "2G", "boot.priority": "5"}, nil)
	if err != nil || len(restart) != 0 || s.Boot.Priority != 5 {
		t.Fatalf("%v %v", err, restart)
	}
	if _, err := ApplyConfig(&s, map[string]string{"nic.eth0.mtu": "1500"}, nil); err != nil || s.Network[0].MTU != 1500 {
		t.Fatalf("%v %+v", err, s.Network)
	}
	// there is one spelling of a device key
	if _, err := ApplyConfig(&s, map[string]string{"network.eth0.mtu": "1400"}, nil); err == nil {
		t.Fatal("network.eth0.mtu is no key: the device keys are nic.<device>.<field>")
	}
}

func TestApplyConfigUnsetAndDevices(t *testing.T) {
	s := JailSpec{Network: []NetworkAttach{{Network: "lan", IPv4: "auto"}, {Network: "dmz"}}, Resources: Resources{Memory: "1G"}, Volumes: []VolumeAttach{{Name: "data", Mount: "/d"}}}
	restart, err := ApplyConfig(&s, nil, []string{"limits.memory", "nic.eth1", "disk.data"})
	if err != nil {
		t.Fatal(err)
	}
	if s.Resources.Memory != "" || len(s.Network) != 1 || s.Network[0].Name != "eth0" || len(s.Volumes) != 0 {
		t.Fatalf("%+v", s)
	}
	if !reflect.DeepEqual(restart, []string{"disk.data", "limits.memory", "nic.eth1"}) {
		t.Fatal(restart)
	}
	if _, err := ApplyConfig(&s, nil, []string{"nic.eth7"}); err != nil {
		t.Fatalf("removing a device that is not there is not an error: %v", err)
	}
}

func TestApplyConfigRejectsAndIsAtomic(t *testing.T) {
	s := JailSpec{Resources: Resources{CPU: 1}}
	for name, set := range map[string]map[string]string{
		"unknown":        {"limits.ram": "1G"},
		"bad int":        {"limits.cpu": "many"},
		"range":          {"limits.cpu": "100000"},
		"bad size":       {"limits.memory": "lots"},
		"zero size":      {"limits.memory": "0"},
		"bad bool":       {"boot.autostart": "maybe"},
		"bad enum":       {"update.strategy": "yolo"},
		"bad mtu":        {"nic.eth0.mtu": "10"},
		"bad address":    {"nic.eth0.ipv4": "fe80::1"},
		"bad v6":         {"nic.eth0.ipv6": "10.0.0.1"},
		"bad mac":        {"nic.eth0.mac": "AA:BB"},
		"device name":    {"nic.Bad_Name.network": "lan"},
		"devfs list":     {"devfs.x.device": "kmem"},
		"mount path":     {"disk.d.mount": "../etc"},
		"listen":         {"proxy.p.listen": "nonsense"},
		"port":           {"proxy.p.jail_port": "70000"},
		"proto":          {"proxy.p.proto": "icmp"},
		"env name":       {"env.1X": "y"},
		"rate":           {"nic.eth0.egress": "fast"},
		"hostname":       {"hostname": "bad host!"},
		"list item":      {"boot.depends": "Bad Name"},
		"injection":      {"firewall.policies": "x\"; rm"},
		"profile loop":   {"profiles": "UPPER"},
		"partial values": {"limits.cpu": "2", "limits.memory": "zzz"},
	} {
		before := s
		if _, err := ApplyConfig(&s, set, nil); err == nil {
			t.Errorf("%s: accepted", name)
		} else if !IsCode(err, CodeInvalid) {
			t.Errorf("%s: %v", name, err)
		}
		if !reflect.DeepEqual(before, s) {
			t.Errorf("%s: the spec changed although the call failed: %+v", name, s)
		}
	}
	if _, err := ApplyConfig(&s, map[string]string{"limits.cpu": "2"}, []string{"nope"}); err == nil || s.Resources.CPU != 1 {
		t.Fatalf("%v %+v", err, s)
	}
}

func prof(name string, cfg map[string]string) Profile {
	return Profile{Metadata: ObjectMeta{Name: name}, Spec: ProfileSpec{Config: cfg}}
}

func TestExpandedConfigMergesInOrderAndReportsSources(t *testing.T) {
	jail := JailSpec{Image: "fb", Profiles: []string{"base", "web"},
		Resources: Resources{Memory: "4G"},
		Network:   []NetworkAttach{{Network: "lan", IPv4: "10.0.0.5", MTU: 1300}}}
	base := prof("base", map[string]string{"limits.memory": "1G", "limits.cpu": "1", "boot.autostart": "true", "nic.eth0.mtu": "9000", "nic.eth1.network": "mgmt", "env.TZ": "UTC"})
	web := prof("web", map[string]string{"limits.cpu": "4", "proxy.http.listen": ":80", "proxy.http.jail_port": "8080", "nic.eth1.mtu": "1400", "disk.data.mount": "/var/db"})
	got, src := ExpandedConfig(jail, []Profile{base, web})
	if got.Resources.Memory != "4G" || got.Resources.CPU != 4 || !got.Boot.Autostart || got.Env["TZ"] != "UTC" {
		t.Fatalf("%+v", got)
	}
	if len(got.Network) != 2 || got.Network[0].MTU != 1300 || got.Network[0].IPv4 != "10.0.0.5" || got.Network[1].Name != "eth1" ||
		got.Network[1].Network != "mgmt" || got.Network[1].MTU != 1400 {
		t.Fatalf("device by device: %+v", got.Network)
	}
	if len(got.Proxy) != 1 || got.Proxy[0].JailPort != 8080 || len(got.Volumes) != 1 {
		t.Fatalf("%+v", got)
	}
	for k, want := range map[string]string{"limits.memory": "jail", "limits.cpu": "web", "boot.autostart": "base", "nic.eth0.mtu": "jail",
		"nic.eth1.network": "base", "nic.eth1.mtu": "web", "env.TZ": "base", "proxy.http.listen": "web", "image": "jail"} {
		if src[k] != want {
			t.Errorf("source of %s: %q, want %q", k, src[k], want)
		}
	}
	// The jail's own spec is untouched.
	if jail.Resources.CPU != 0 || len(jail.Network) != 1 {
		t.Fatalf("%+v", jail)
	}
	// Without profiles the spec comes back as it was.
	same, srcs := ExpandedConfig(jail, nil)
	if !reflect.DeepEqual(same.Resources, jail.Resources) || srcs["limits.memory"] != "jail" {
		t.Fatal(same, srcs)
	}
}

func TestProfilesAllowOnlyProfileKeys(t *testing.T) {
	if err := ValidateProfile(ProfileSpec{Config: map[string]string{"limits.memory": "1G", "nic.eth1.network": "lan", "proxy.p.listen": ":80"}}); err != nil {
		t.Fatal(err)
	}
	for _, k := range []string{"hostname", "image", "profiles", "nic.eth0.ipv4", "nic.eth0.mac"} {
		if err := ValidateProfile(ProfileSpec{Config: map[string]string{k: "x"}}); err == nil || !strings.Contains(err.Error(), k) {
			t.Errorf("%s allowed in a profile: %v", k, err)
		}
	}
	if err := ValidateProfile(ProfileSpec{Config: map[string]string{"limits.memory": "oops"}}); err == nil {
		t.Fatal("a bad value was accepted")
	}
}

func TestConfigValuesRoundTrip(t *testing.T) {
	var s JailSpec
	set := map[string]string{"limits.cpu": "2", "nic.eth0.network": "lan", "nic.eth0.ipv4": "auto", "disk.d.mount": "/x", "env.A": "1", "proxy.p.listen": ":1", "proxy.p.jail_port": "2"}
	if _, err := ApplyConfig(&s, set, nil); err != nil {
		t.Fatal(err)
	}
	for k, v := range set {
		if ConfigValues(s)[k] != v {
			t.Errorf("%s = %q", k, ConfigValues(s)[k])
		}
	}
	var t2 JailSpec
	if _, err := ApplyConfig(&t2, ConfigValues(s), nil); err != nil || !reflect.DeepEqual(ConfigValues(t2), ConfigValues(s)) {
		t.Fatalf("%v\n%v\n%v", err, ConfigValues(t2), ConfigValues(s))
	}
}

// zfs.delegation is a boolean of the jail itself: global administrators set it, and a profile cannot carry it.
func TestZFSDelegationKey(t *testing.T) {
	var s JailSpec
	restart, err := ApplyConfig(&s, map[string]string{"zfs.delegation": "true"}, nil)
	if err != nil || !s.Delegate || !reflect.DeepEqual(restart, []string{"zfs.delegation"}) {
		t.Fatalf("%v %v %+v", err, restart, s)
	}
	if v := ConfigValues(s); v["zfs.delegation"] != "true" {
		t.Fatalf("%v", v)
	}
	if _, err := ApplyConfig(&s, map[string]string{"zfs.delegation": "maybe"}, nil); err == nil || !s.Delegate {
		t.Fatalf("not a boolean: %v %+v", err, s)
	}
	if _, err := ApplyConfig(&s, nil, []string{"zfs.delegation"}); err != nil || s.Delegate {
		t.Fatalf("unset: %v %+v", err, s)
	}
	for _, k := range ConfigKeys() {
		if k.Name == "zfs.delegation" && k.Profile {
			t.Error("a profile may carry zfs.delegation")
		}
	}
}

func TestSysVIPCKey(t *testing.T) {
	var s JailSpec
	restart, err := ApplyConfig(&s, map[string]string{"sysvipc": "true"}, nil)
	if err != nil || !s.SysVIPC || !reflect.DeepEqual(restart, []string{"sysvipc"}) {
		t.Fatalf("%v %v %+v", err, restart, s)
	}
	if v := ConfigValues(s); v["sysvipc"] != "true" {
		t.Fatalf("%v", v)
	}
	if _, err := ApplyConfig(&s, map[string]string{"sysvipc": "inherit"}, nil); err == nil || !s.SysVIPC {
		t.Fatalf("not a boolean: %v %+v", err, s)
	}
	if _, err := ApplyConfig(&s, nil, []string{"sysvipc"}); err != nil || s.SysVIPC {
		t.Fatalf("unset: %v %+v", err, s)
	}
	// a profile may carry it
	eff, src := ExpandedConfig(JailSpec{}, []Profile{{Metadata: ObjectMeta{Name: "db"}, Spec: ProfileSpec{Config: map[string]string{"sysvipc": "true"}}}})
	if !eff.SysVIPC || src["sysvipc"] != "db" {
		t.Fatalf("%+v %v", eff, src)
	}
}

// boot.stop_timeout is the seconds a jail has to shut down by itself; it is written at the next start.
func TestStopTimeoutKey(t *testing.T) {
	var s JailSpec
	restart, err := ApplyConfig(&s, map[string]string{"boot.stop_timeout": "60"}, nil)
	if err != nil || s.Boot.StopTimeout != 60 || !reflect.DeepEqual(restart, []string{"boot.stop_timeout"}) {
		t.Fatalf("%v %v %+v", err, restart, s.Boot)
	}
	if v := ConfigValues(s); v["boot.stop_timeout"] != "60" {
		t.Fatalf("%v", v)
	}
	var t2 JailSpec
	if _, err := ApplyConfig(&t2, ConfigValues(s), nil); err != nil || t2.Boot.StopTimeout != 60 {
		t.Fatalf("round trip: %v %+v", err, t2.Boot)
	}
	for _, bad := range []string{"-1", "3601", "slow"} {
		if _, err := ApplyConfig(&JailSpec{}, map[string]string{"boot.stop_timeout": bad}, nil); err == nil {
			t.Errorf("%q is accepted", bad)
		}
	}
	if _, err := ApplyConfig(&s, nil, []string{"boot.stop_timeout"}); err != nil || s.Boot.StopTimeout != 0 {
		t.Fatalf("unset: %v %+v", err, s.Boot)
	}
}
