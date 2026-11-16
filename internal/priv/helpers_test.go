package priv

import (
	"context"
	"encoding/json"
	fmt "fmt"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"jailops.net/jailops/internal/sys/ifconfig"
	"jailops.net/jailops/internal/sys/jailos"
	"jailops.net/jailops/internal/sys/pfctl"
	"jailops.net/jailops/internal/sys/run"
	"jailops.net/jailops/internal/sys/zfs"
	"jailops.net/jailops/sdk/api"
)

type env struct {
	t      *testing.T
	base   string
	cfg    Config
	zfs    *zfs.Fake
	jails  *jailos.Fake
	pf     *pfctl.Fake
	net    *ifconfig.Fake
	runner *run.Fake
	jexec  string
	local  *Local
}

func mustWrite(t *testing.T, path, content string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}

func newEnv(t *testing.T) *env {
	t.Helper()
	dir, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	e := &env{t: t, base: dir}
	e.cfg = Config{
		StorageRoots: []string{"tank/jailops"},
		StorageFile:  filepath.Join(dir, "priv.d", "storage.conf"),
		MountBase:    filepath.Join(dir, "jailops"),
		ConfDir:      filepath.Join(dir, "etc", "jails"),
		StateDir:     filepath.Join(dir, "jailops", "state"),
		HelperPath:   "/usr/local/libexec/jailops-priv",
	}
	for _, d := range []string{e.cfg.MountBase, e.cfg.ConfDir, e.cfg.StateDir} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	// a storage root's directory has mode 0700 (checkRootDir)
	if err := os.Chmod(e.cfg.MountBase, 0o700); err != nil {
		t.Fatal(err)
	}
	e.jexec = filepath.Join(dir, "jexec")
	// A stand-in for jexec(8): it records its arguments and runs the command
	// (after the optional -U user and the jail name) in this process tree.
	script := "#!/bin/sh\nprintf '%s\\n' \"$@\" > \"$0.args\"\nif [ \"$1\" = -U ]; then shift 2; fi\nshift\nexec \"$@\"\n"
	if err := os.WriteFile(e.jexec, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	e.zfs = zfs.NewFake("tank")
	if err := e.zfs.Create(context.Background(), zfs.CreateOpts{Name: "tank/jailops", Props: map[string]string{"jailops:managed": "on", "mountpoint": e.cfg.MountBase}}); err != nil {
		t.Fatal(err)
	}
	e.jails = jailos.NewFake()
	e.pf = pfctl.NewFake()
	e.net = ifconfig.NewFake(ifconfig.Options{})
	e.net.AddForeign("em0", true) // the host's uplink: never JailOps's
	// a bridge an administrator made by hand (ifconfig bridge create; ifconfig bridge0 name mybr): never JailOps's
	e.net.AddIface(ifconfig.Iface{Name: "mybr", Groups: []string{"bridge"}, Flags: []string{"UP"}})
	// an epair, through which the fake NDP routes its jail addresses (jo30gb)
	if _, _, err := e.net.EpairCreate(context.Background(), "jo30g"); err != nil {
		t.Fatal(err)
	}
	// a network in IPv6 proxy mode on the uplink: the prefix the NDP tests answer for
	proxyNet, _ := json.Marshal(map[string]any{"kind": "Network", "metadata": api.ObjectMeta{Name: "edge", UUID: "bbbb-1111-2222"},
		"spec": api.NetworkSpec{Uplink: "em0", IPv6: &api.IPv6Net{Mode: api.IPv6Proxy, Subnet: "2001:db8:1:2:100::/80"}}})
	mustWrite(t, filepath.Join(e.cfg.StateDir, "objects", "Network", "bbbb-1111-2222.json"), string(proxyNet))
	e.runner = run.NewFake()
	l, err := NewLocal(e.cfg, Deps{ZFS: e.zfs, Jails: e.jails, PF: e.pf, Net: e.net, Runner: e.runner, Jexec: e.jexec,
		NDP: newFakeNDP(dir)}, WithoutChown())
	if err != nil {
		t.Fatal(err)
	}
	e.local = l
	e.cfg = l.Config()
	return e
}

// managedDS creates a dataset below the root with jailops:managed=on.
func (e *env) managedDS(name string) {
	e.t.Helper()
	err := e.zfs.Create(context.Background(), zfs.CreateOpts{Name: name, Parents: true, Props: map[string]string{"jailops:managed": "on"}})
	if err != nil {
		e.t.Fatal(err)
	}
}

const goodConf = `# Managed by JailOps. Do not edit; changes are overwritten.
alpha_web {
	path = "%s";
	host.hostname = "web.example.org";
	vnet;
	vnet.interface = "jo0123456789a0b";
	devfs_ruleset = 4;
	mount.devfs;
	exec.clean;
	exec.prestart = "/usr/local/libexec/jailops-priv hook prestart ${name}";
	exec.poststart = "/usr/local/libexec/jailops-priv hook poststart ${name}";
	exec.prestop = "/usr/local/libexec/jailops-priv hook prestop ${name}";
	exec.poststop = "/usr/local/libexec/jailops-priv hook poststop ${name}";
	exec.consolelog = "/var/log/jailops/jail_${name}_console.log";
	exec.start = "/bin/sh /etc/rc";
	exec.stop = "/bin/sh /etc/rc.shutdown jail";
	enforce_statfs = 2;
	securelevel = 2;
	osrelease = "15.0-RELEASE";
}
`

func (e *env) goodConf() string {
	return sprintf(goodConf, filepath.Join(e.cfg.MountBase, "projects", "alpha", "jails", "web", "root"))
}

// storeLan stores a network with this IPv4 subnet: the addresses and routes a test puts on an epair lie in it.
func (e *env) storeLan(t *testing.T, subnet string) {
	t.Helper()
	b, _ := json.Marshal(map[string]any{"kind": "Network", "metadata": api.ObjectMeta{Name: "lan", UUID: "cccc-1111-2222"},
		"spec": api.NetworkSpec{Uplink: "em0", IPv4: &api.IPv4Net{Subnet: subnet, Gateway: subnet[:strings.LastIndex(subnet, ".")] + ".1"}}})
	mustWrite(t, filepath.Join(e.cfg.StateDir, "objects", "Network", "cccc-1111-2222.json"), string(b))
}

// goodConfNamed is goodConf for the jail called name (<project>_<jail>), at the root path that name has.
func (e *env) goodConfNamed(name string) string {
	proj, jail, _ := strings.Cut(name, "_")
	conf := strings.Replace(e.goodConf(), "alpha_web {", name+" {", 1)
	return strings.Replace(conf, filepath.Join(e.cfg.MountBase, "projects", "alpha", "jails", "web", "root"),
		filepath.Join(e.cfg.MountBase, "projects", proj, "jails", jail, "root"), 1)
}

func sprintf(f string, a ...any) string { return fmt.Sprintf(f, a...) }

func jailosExec(argv ...string) jailos.ExecOpts { return jailos.ExecOpts{Argv: argv} }

type netipPrefix = netip.Prefix

func parsePrefix(s string) (netip.Prefix, error) { return netip.ParsePrefix(s) }

type jailosExecOpts = jailos.ExecOpts

func removeAll(p string) error { return os.RemoveAll(p) }

// conf makes jail key a managed jail (its conf file exists).
func (e *env) conf(t *testing.T, key string) {
	t.Helper()
	mustWrite(t, filepath.Join(e.cfg.ConfDir, key+".conf"), e.goodConfNamed(key))
}
