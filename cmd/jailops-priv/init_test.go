package main

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"jailops.net/jailops/internal/daemon"
)

type recorder struct {
	cmds  []string
	exist map[string]bool // datasets that exist
	flag  map[string]string
	mp    map[string]string // the mountpoint property of a dataset (zfs get mountpoint); unset prints the mount the options ask for
	// root is the dataset mounted at / (rootErr: none); managed is what a recursive zfs get of jailops:managed prints
	root    string
	rootErr bool
	managed string
}

func (r *recorder) run(name string, args ...string) (string, error) {
	line := name + " " + strings.Join(args, " ")
	r.cmds = append(r.cmds, line)
	switch {
	case name == "zpool":
		return args[len(args)-1], nil
	case name == "zfs" && args[0] == "list" && args[len(args)-1] == "/":
		if r.rootErr || r.root == "" {
			return "cannot open '/': not a ZFS file system", fmt.Errorf("exit 1")
		}
		return r.root, nil
	case name == "zfs" && args[0] == "get" && slices.Contains(args, "-r"):
		return r.managed, nil
	case name == "zfs" && args[0] == "list":
		ds := args[len(args)-1]
		if r.exist[ds] {
			return ds, nil
		}
		return "", fmt.Errorf("dataset does not exist")
	case name == "zfs" && args[0] == "get" && slices.Contains(args, "mountpoint"):
		return r.mp[args[len(args)-1]], nil
	case name == "zfs" && args[0] == "get":
		return r.flag[args[len(args)-1]], nil
	case name == "zfs" && args[0] == "create":
		r.exist[args[len(args)-1]] = true
	}
	return "", nil
}

func newInit(t *testing.T, r *recorder) (*initOptions, string) {
	root := t.TempDir()
	return &initOptions{pool: "tank", mount: "/usr/local/jailops", user: "jailops", group: "jailops",
		etc: "/usr/local/etc/jailops", dbDir: "/var/db/jailops", root: root, run: r.run,
		lookupUser: func(string) (int, int, error) { return 1001, 1001, nil },
		lookupGrp:  func(string) (int, int, error) { return 0, 1001, nil },
		chown:      func(string, int, int) error { return nil }}, root
}

func TestInitCreatesWhatTheDaemonCannot(t *testing.T) {
	r := &recorder{exist: map[string]bool{}, flag: map[string]string{}}
	o, root := newInit(t, r)
	var out bytes.Buffer
	if err := o.do(&out); err != nil {
		t.Fatal(err)
	}
	all := strings.Join(r.cmds, "\n")
	for _, want := range []string{"zfs create -o mountpoint=/usr/local/jailops -o jailops:managed=on tank/jailops", "zfs create -o mountpoint=/var/db/jailops/state -o jailops:managed=on tank/jailops/state"} {
		if !strings.Contains(all, want) {
			t.Errorf("missing %q in\n%s", want, all)
		}
	}
	// the files it writes are valid configuration
	if _, err := daemon.Load(filepath.Join(root, "usr/local/etc/jailops/jailopsd.yaml")); err != nil {
		t.Fatalf("jailopsd.yaml: %v\n%s", err, out.String())
	}
	var po options
	fs := newFlags(&po, &out)
	if err := loadConfigFile(fs, filepath.Join(root, "usr/local/etc/jailops/priv.conf"), true); err != nil {
		t.Fatalf("priv.conf: %v", err)
	}
	if po.mountBase != "/usr/local/jailops" || len(po.storage) != 1 || po.storage[0] != "tank/jailops" || po.workDir != "/var/tmp/jailops" {
		t.Fatalf("priv.conf = %+v", po)
	}
	if fi, err := os.Stat(filepath.Join(root, "usr/local/etc/jailops/priv.conf")); err != nil || fi.Mode().Perm() != 0o600 {
		t.Fatalf("priv.conf mode: %v %v", fi, err)
	}
	// the directory of the files of API log sinks (logging.secrets_dir): root's, the group reads
	if fi, err := os.Stat(filepath.Join(root, "usr/local/etc/jailops/sinks")); err != nil || !fi.IsDir() || fi.Mode().Perm() != 0o750 {
		t.Fatalf("sinks directory: %v %v", fi, err)
	}
}

func TestInitIsIdempotentAndNeverOverwrites(t *testing.T) {
	r := &recorder{exist: map[string]bool{}, flag: map[string]string{}}
	o, root := newInit(t, r)
	if err := o.do(&bytes.Buffer{}); err != nil {
		t.Fatal(err)
	}
	conf := filepath.Join(root, "usr/local/etc/jailops/priv.conf")
	if err := os.WriteFile(conf, []byte("# mine\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	r.flag["tank/jailops"] = "on\tlocal"
	r.cmds = nil
	var out bytes.Buffer
	if err := o.do(&out); err != nil {
		t.Fatal(err)
	}
	for _, c := range r.cmds {
		if strings.Contains(c, "create") {
			t.Errorf("a second run created something: %s", c)
		}
	}
	if b, _ := os.ReadFile(conf); string(b) != "# mine\n" {
		t.Fatalf("priv.conf was overwritten: %q", b)
	}
	if !strings.Contains(out.String(), "exists, left as it is") {
		t.Fatalf("%s", out.String())
	}
}

func TestInitRefusesWhatItDoesNotOwn(t *testing.T) {
	r := &recorder{exist: map[string]bool{"tank/jailops": true}, flag: map[string]string{"tank/jailops": "-\t-"}}
	o, _ := newInit(t, r)
	if err := o.do(&bytes.Buffer{}); err == nil || !strings.Contains(err.Error(), "not marked jailops:managed=on") {
		t.Fatalf("an existing dataset that is not marked was taken over: %v", err)
	}
	for _, bad := range []*initOptions{{pool: ""}, {pool: "tank/x"}, {pool: "tank", dataset: "other/jailops"}, {pool: "tank", mount: "relative"}, {pool: "tank", mount: "/"}} {
		bad.run = r.run
		if bad.mount == "" {
			bad.mount = "/usr/local/jailops"
		}
		if err := bad.do(&bytes.Buffer{}); err == nil {
			t.Errorf("accepted %+v", bad)
		}
	}
}

func TestInitDryRunChangesNothing(t *testing.T) {
	r := &recorder{exist: map[string]bool{}, flag: map[string]string{}}
	o, root := newInit(t, r)
	o.dryRun = true
	var out bytes.Buffer
	if err := o.do(&out); err != nil {
		t.Fatal(err)
	}
	for _, c := range r.cmds {
		if strings.Contains(c, "create") || strings.HasPrefix(c, "pw ") {
			t.Errorf("dry run executed %s", c)
		}
	}
	if _, err := os.Stat(filepath.Join(root, "usr")); err == nil {
		t.Error("dry run wrote files")
	}
	if !strings.Contains(out.String(), "creating dataset tank/jailops") {
		t.Fatalf("%s", out.String())
	}
}

// -web writes the two settings that put the console on a browser: the TLS listener and web.enabled. Without it the
// configuration has neither (the console is off by default).
func TestInitWebTurnsTheConsoleOn(t *testing.T) {
	for _, web := range []bool{false, true} {
		r := &recorder{exist: map[string]bool{}, flag: map[string]string{}}
		o, root := newInit(t, r)
		o.web, o.webAddress = web, ":39110"
		var out bytes.Buffer
		if err := o.do(&out); err != nil {
			t.Fatal(err)
		}
		cfg, err := daemon.Load(filepath.Join(root, "usr/local/etc/jailops/jailopsd.yaml"))
		if err != nil {
			t.Fatalf("web=%v: %v", web, err)
		}
		if cfg.UI() != web {
			t.Errorf("web=%v: console served = %v", web, cfg.UI())
		}
		if got := cfg.Listen.HTTPS.Address; (got == ":39110") != web {
			t.Errorf("web=%v: https address %q", web, got)
		}
	}
}

// An installed host keeps the mount point of its storage root: init again on a release with another default must not
// point mount-base elsewhere (the helper would then refuse every path of the images and jails there).
func TestInitKeepsTheMountPointOfAnExistingStorageRoot(t *testing.T) {
	r := &recorder{exist: map[string]bool{"tank/jailops": true, "tank/jailops/state": true},
		flag: map[string]string{"tank/jailops": "on\tlocal"}, mp: map[string]string{"tank/jailops": "/jailops"}}
	o, _ := newInit(t, r)
	var out bytes.Buffer
	if err := o.do(&out); err != nil {
		t.Fatal(err)
	}
	if o.mount != "/jailops" || !strings.Contains(out.String(), "already mounted at /jailops: keeping it") {
		t.Fatalf("mount %q\n%s", o.mount, out.String())
	}
}

func TestInitRefusesAMountThatContradictsTheExistingStorageRoot(t *testing.T) {
	r := &recorder{exist: map[string]bool{"tank/jailops": true, "tank/jailops/state": true},
		flag: map[string]string{"tank/jailops": "on\tlocal"}, mp: map[string]string{"tank/jailops": "/jailops"}}
	o, _ := newInit(t, r)
	o.mountSet = true
	err := o.do(&bytes.Buffer{})
	if err == nil || !strings.Contains(err.Error(), "is mounted at /jailops, not at /usr/local/jailops") {
		t.Fatalf("%v", err)
	}
}
