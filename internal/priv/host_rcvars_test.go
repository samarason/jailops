package priv

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"jailops.net/jailops/sdk/api"
)

// A restore puts back the module's own rc.conf variables and its block of ntp.conf, nothing else: what root changed
// in rc.conf or ntp.conf after the snapshot stays, and the diff names only the module's variables.
func TestHostRestoreKeepsTheRestOfRCConf(t *testing.T) {
	e, h := newHostEnv(t, "identity")
	c := hostWire(t, e)
	etc := filepath.Join(e.base, "etc")
	res, err := c.HostIdentityApply(admin(), goodSpec(), false)
	if err != nil {
		t.Fatal(err)
	}
	// root edits rc.conf and ntp.conf by hand after the snapshot
	rcPath, ntpPath := filepath.Join(etc, "rc.conf"), filepath.Join(etc, "ntp.conf")
	mustWrite(t, rcPath, readFile(t, rcPath)+"cloned_interfaces=\"lo1\"\nbackup_token=\"s3cr3t-value\"\n")
	mustWrite(t, ntpPath, readFile(t, ntpPath)+"driftfile /var/db/ntpd.drift\n")

	dry, err := c.HostSnapshotRestore(admin(), res.Snapshot, true)
	if err != nil || !dry.Changed {
		t.Fatalf("%+v %v", dry, err)
	}
	for _, not := range []string{"s3cr3t", "backup_token", "cloned_interfaces", "sshd_enable", "ifconfig_em0"} {
		if strings.Contains(dry.Diff, not) || strings.Contains(strings.Join(dry.Actions, "\n"), not) {
			t.Errorf("the restore shows %q:\n%s\n%v", not, dry.Diff, dry.Actions)
		}
	}
	for _, want := range []string{`-hostname="web1.example.org"`, `+hostname="old.example.org"`, `-ntpd_enable="YES"`, `-ntpd_sync_on_start="YES"`} {
		if !strings.Contains(dry.Diff, want) {
			t.Errorf("the diff lacks %q:\n%s", want, dry.Diff)
		}
	}
	if _, err := c.HostSnapshotRestore(admin(), res.Snapshot, false); err != nil {
		t.Fatal(err)
	}
	wantRC := origRC + "cloned_interfaces=\"lo1\"\nbackup_token=\"s3cr3t-value\"\n"
	if got := readFile(t, rcPath); got != wantRC {
		t.Errorf("rc.conf:\n%s\nwant:\n%s", got, wantRC)
	}
	if got := readFile(t, ntpPath); got != origNTP+"driftfile /var/db/ntpd.drift\n" {
		t.Errorf("ntp.conf:\n%s", got)
	}
	if readFile(t, filepath.Join(etc, "resolv.conf")) != origResolv || h.hostname != "old.example.org" {
		t.Error("resolv.conf or the host name did not come back")
	}
	// the restore's own snapshot recorded the variables too, and undoing it brings the module's values back only
	if _, err := c.HostSnapshotRestore(admin(), "latest", false); err != nil {
		t.Fatal(err)
	}
	rc := parseRC(readFile(t, rcPath))
	if rc["hostname"] != "web1.example.org" || rc["ntpd_enable"] != "YES" || !strings.Contains(readFile(t, rcPath), "backup_token") {
		t.Errorf("undo of the restore: %v", rc)
	}
}

// A snapshot of the earlier format (a copy of rc.conf) puts back only the module's variables from that copy, and
// a value the helper does not write back is refused rather than written.
func TestHostRestoreOfAnOldSnapshot(t *testing.T) {
	e, _ := newHostEnv(t, "identity")
	c := hostWire(t, e)
	etc := filepath.Join(e.base, "etc")
	old := func(name, rcCopy string) {
		t.Helper()
		dir := filepath.Join(e.cfg.HostDir, "snapshots", name)
		mustWrite(t, filepath.Join(dir, "rc.conf"), rcCopy)
		m := hostManifest{Module: api.HostModuleIdentity, Time: time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC), Reason: "apply",
			Files: []hostSnapFile{{Name: "rc.conf", Exists: true, Mode: 0o644}}}
		b, _ := json.Marshal(m)
		mustWrite(t, filepath.Join(dir, "snapshot.json"), string(b))
		os.Chmod(e.cfg.HostDir, 0o700)
	}
	old("20261001T000000Z", "hostname=\"legacy.example.org\"\nsshd_enable=\"NO\"\nifconfig_em0=\"inet 192.0.2.99/24\"\n")
	if _, err := c.HostSnapshotRestore(admin(), "20261001T000000Z", false); err != nil {
		t.Fatal(err)
	}
	got := readFile(t, filepath.Join(etc, "rc.conf"))
	if want := "hostname=\"legacy.example.org\"\nifconfig_em0=\"DHCP\"\nsshd_enable=\"YES\"\n"; got != want {
		t.Errorf("rc.conf:\n%s", got)
	}
	old("20261002T000000Z", "hostname=\"$(reboot)\"\n")
	if _, err := c.HostSnapshotRestore(admin(), "20261002T000000Z", true); !api.IsCode(err, api.CodeInvalid) {
		t.Errorf("a value with a shell expansion: %v", err)
	}
	if readFile(t, filepath.Join(etc, "rc.conf")) != got {
		t.Error("rc.conf changed")
	}
}

// A firewall change that is reverted (by the timer, or at once) puts back pf.conf whole and the two variables, and
// leaves a line root added to rc.conf while the change waited.
func TestHostFWRevertKeepsTheRestOfRCConf(t *testing.T) {
	for _, how := range []string{"timer", "revert"} {
		t.Run(how, func(t *testing.T) {
			f := newFWEnv(t, "firewall")
			c := hostWire(t, f.env)
			rcPath := filepath.Join(f.etc, "rc.conf")
			res, err := c.HostFirewallApply(admin(), fwReq(fwSpec(), false))
			if err != nil || res.Pending == nil {
				t.Fatalf("%+v %v", res, err)
			}
			mustWrite(t, rcPath, readFile(t, rcPath)+"zfs_enable=\"YES\"\n")
			if how == "timer" {
				f.advance(61 * time.Second)
				f.timer.fire(t)
			} else if _, err := c.HostPendingRevert(admin(), ""); err != nil {
				t.Fatal(err)
			}
			if got := readFile(t, rcPath); got != origRC+"zfs_enable=\"YES\"\n" {
				t.Errorf("rc.conf:\n%s", got)
			}
			if readFile(t, filepath.Join(f.etc, "pf.conf")) != origPF {
				t.Error("pf.conf is not the original, byte for byte")
			}
		})
	}
}

// At boot (revert-pending) only the files and the variables go back, the same way.
func TestHostFWBootRevertKeepsTheRestOfRCConf(t *testing.T) {
	f := newFWEnv(t, "firewall")
	c := hostWire(t, f.env)
	rcPath := filepath.Join(f.etc, "rc.conf")
	if _, err := c.HostFirewallApply(admin(), fwReq(fwSpec(), false)); err != nil {
		t.Fatal(err)
	}
	mustWrite(t, rcPath, readFile(t, rcPath)+"zfs_enable=\"YES\"\n")
	f.reopen(t, "firewall")
	if _, err := f.local.RevertPendingAtBoot(context.Background()); err != nil {
		t.Fatal(err)
	}
	if got := readFile(t, rcPath); got != origRC+"zfs_enable=\"YES\"\n" {
		t.Errorf("rc.conf:\n%s", got)
	}
}

// host-dir must be a plain directory of its owner (root; the test's user here) that nobody else can read or write:
// a copy in it goes to /etc on a restore. Otherwise every host operation that uses it is refused.
func TestHostDirOwnerAndMode(t *testing.T) {
	for _, tc := range []struct {
		name  string
		setup func(t *testing.T, dir string, l *Local)
	}{
		{"mode 0755", func(t *testing.T, dir string, _ *Local) { os.Chmod(dir, 0o755) }},
		{"mode 0710", func(t *testing.T, dir string, _ *Local) { os.Chmod(dir, 0o710) }},
		{"another owner", func(t *testing.T, _ string, l *Local) { l.hostDirUID = uint32(os.Getuid()) + 1 }},
		{"a symlink", func(t *testing.T, dir string, _ *Local) {
			real := dir + ".real"
			if err := os.Rename(dir, real); err != nil {
				t.Fatal(err)
			}
			if err := os.Symlink(real, dir); err != nil {
				t.Fatal(err)
			}
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			e, _ := newHostEnv(t, "identity")
			if _, err := e.local.HostIdentityApply(admin(), goodSpec(), false); err != nil {
				t.Fatal(err)
			}
			tc.setup(t, e.cfg.HostDir, e.local)
			if _, err := e.local.HostSnapshots(context.Background()); !api.IsCode(err, api.CodeForbidden) {
				t.Errorf("list: %v", err)
			}
			if _, err := e.local.HostSnapshotRestore(admin(), "latest", false); !api.IsCode(err, api.CodeForbidden) {
				t.Errorf("restore: %v", err)
			}
			if _, err := e.local.HostIdentityApply(admin(), api.HostIdentitySpec{Hostname: "other.example.org"}, false); !api.IsCode(err, api.CodeForbidden) {
				t.Errorf("apply: %v", err)
			}
		})
	}
}
