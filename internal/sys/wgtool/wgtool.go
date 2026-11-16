// Package wgtool runs the commands behind WireGuard interfaces: wg(8) for keys, configuration and state, and
// ifconfig(8) and route(8) for the interface itself. It validates nothing beyond the shape of its arguments; the
// privileged helper decides what may be done (internal/priv/wireguard.go). Keys never appear on a command line:
// `wg pubkey` reads the private key on standard input, and configurations are read from a file.
//
// UNVERIFIED on FreeBSD 15.1: `ifconfig wg create` with a rename to a name holding '-', `wg syncconf`, and the dump
// format of the wg program shipped there.
package wgtool

import (
	"context"
	"net/netip"
	"os"
	"strings"
	"time"

	"jailops.net/jailops/internal/sys/ifconfig"
	"jailops.net/jailops/internal/sys/run"
	"jailops.net/jailops/internal/wireguard"
	"jailops.net/jailops/sdk/api"
)

// Tool runs the commands. Path is the wg program (see Locate).
type Tool struct {
	R    run.Runner
	Path string
}

const timeout = 20 * time.Second

// Locate returns the first of wireguard.Binaries that is a regular file owned by root, executable and writable by
// nobody else, or "". stat is os.Stat in production.
func Locate(stat func(string) (os.FileInfo, error), owner func(os.FileInfo) (uid uint32, ok bool)) string {
	for _, p := range wireguard.Binaries {
		fi, err := stat(p)
		if err != nil || !fi.Mode().IsRegular() || fi.Mode().Perm()&0o111 == 0 || fi.Mode().Perm()&0o022 != 0 {
			continue
		}
		if uid, ok := owner(fi); !ok || uid != 0 {
			continue
		}
		return p
	}
	return ""
}

func (t Tool) wg(ctx context.Context, stdin string, args ...string) (string, error) {
	if t.Path == "" {
		return "", api.Errorf(api.CodeUnverified, "the wg program is not installed").
			WithHint("pkg install wireguard-tools (it installs " + wireguard.Binaries[1] + ")")
	}
	c := run.Cmd{Name: t.Path, Args: args, Timeout: timeout}
	if stdin != "" {
		c.Stdin = strings.NewReader(stdin)
	}
	res, err := t.R.Run(ctx, c)
	if err != nil {
		if ee, ok := run.IsExit(err); ok {
			return "", api.Errorf(api.CodeInternal, "wg %s: %s", args[0], firstLine(ee.Stderr))
		}
		return "", api.Errorf(api.CodeInternal, "wg %s: %v", args[0], err)
	}
	return string(res.Stdout), nil
}

func firstLine(s string) string {
	s = strings.TrimSpace(s)
	if i := strings.IndexByte(s, '\n'); i >= 0 {
		s = s[:i]
	}
	if len(s) > 200 {
		s = s[:200]
	}
	return s
}

// key reads one key from a command's output, never quoting it in an error.
func key(out, what string) (string, error) {
	k := strings.TrimSpace(out)
	if !wireguard.ValidKey(k) {
		return "", api.Errorf(api.CodeInternal, "wg %s printed something that is not a key", what)
	}
	return k, nil
}

// GenKey runs `wg genkey`.
func (t Tool) GenKey(ctx context.Context) (string, error) {
	out, err := t.wg(ctx, "", "genkey")
	if err != nil {
		return "", err
	}
	return key(out, "genkey")
}

// GenPSK runs `wg genpsk`.
func (t Tool) GenPSK(ctx context.Context) (string, error) {
	out, err := t.wg(ctx, "", "genpsk")
	if err != nil {
		return "", err
	}
	return key(out, "genpsk")
}

// PubKey runs `wg pubkey` with the private key on standard input.
func (t Tool) PubKey(ctx context.Context, private string) (string, error) {
	if !wireguard.ValidKey(private) {
		return "", api.Errorf(api.CodeInvalid, "not a private key")
	}
	out, err := t.wg(ctx, private+"\n", "pubkey")
	if err != nil {
		return "", err
	}
	return key(out, "pubkey")
}

// SyncConf runs `wg syncconf <iface> <file>`: it applies the differences only, so peers that did not change keep
// their sessions (setconf would replace every peer).
func (t Tool) SyncConf(ctx context.Context, iface, file string) error {
	_, err := t.wg(ctx, "", "syncconf", iface, file)
	return err
}

// Dump runs `wg show <iface> dump` and parses it; the secrets in the output are dropped by the parser.
func (t Tool) Dump(ctx context.Context, iface string) (wireguard.Dump, error) {
	out, err := t.wg(ctx, "", "show", iface, "dump")
	if err != nil {
		return wireguard.Dump{}, err
	}
	d, ok := wireguard.ParseDump(out)
	if !ok {
		return wireguard.Dump{}, api.Errorf(api.CodeInternal, "wg show %s dump: unexpected output", iface)
	}
	return d, nil
}

func (t Tool) ifconfig(ctx context.Context, args ...string) (string, error) {
	res, err := t.R.Run(ctx, run.Cmd{Name: "ifconfig", Args: args, Timeout: timeout})
	if err != nil {
		if ee, ok := run.IsExit(err); ok {
			low := strings.ToLower(ee.Stderr)
			switch {
			case strings.Contains(low, "does not exist"), strings.Contains(low, "interface not found"):
				return "", api.Errorf(api.CodeNotFound, "ifconfig: %s", firstLine(ee.Stderr))
			case strings.Contains(low, "file exists"), strings.Contains(low, "already exists"):
				return "", api.Errorf(api.CodeAlreadyExists, "ifconfig: %s", firstLine(ee.Stderr))
			}
			return "", api.Errorf(api.CodeInternal, "ifconfig: %s", firstLine(ee.Stderr))
		}
		return "", api.Errorf(api.CodeInternal, "ifconfig: %v", err)
	}
	return string(res.Stdout), nil
}

// Create makes a wg interface and renames it: `ifconfig wg create` prints the kernel's name (wgN), which is
// renamed to name. The new interface is destroyed again when the rename fails.
func (t Tool) Create(ctx context.Context, name string) error {
	out, err := t.ifconfig(ctx, "wg", "create")
	if err != nil {
		return err
	}
	tmp := strings.TrimSpace(out)
	if ifconfig.ValidateIfName(tmp) != nil || !strings.HasPrefix(tmp, "wg") {
		return api.Errorf(api.CodeInternal, "ifconfig wg create returned %q", tmp)
	}
	if tmp == name {
		return nil
	}
	if _, err := t.ifconfig(ctx, tmp, "name", name); err != nil {
		_, _ = t.ifconfig(ctx, tmp, "destroy")
		return err
	}
	return nil
}

// Destroy runs `ifconfig <iface> destroy`.
func (t Tool) Destroy(ctx context.Context, iface string) error {
	_, err := t.ifconfig(ctx, iface, "destroy")
	return err
}

// Describe sets the description.
func (t Tool) Describe(ctx context.Context, iface, desc string) error {
	_, err := t.ifconfig(ctx, iface, "description", desc)
	return err
}

// Up brings the interface up.
func (t Tool) Up(ctx context.Context, iface string) error {
	_, err := t.ifconfig(ctx, iface, "up")
	return err
}

// AddrAdd adds an address; AddrRemove removes one.
func (t Tool) AddrAdd(ctx context.Context, iface string, p netip.Prefix) error {
	_, err := t.ifconfig(ctx, append([]string{iface}, ifconfig.AddrWords(p, "alias")...)...)
	return err
}

// AddrRemove removes an address.
func (t Tool) AddrRemove(ctx context.Context, iface string, p netip.Prefix) error {
	_, err := t.ifconfig(ctx, append([]string{iface}, ifconfig.AddrWords(p, "-alias")...)...)
	return err
}

// List reads every interface (ifconfig -a).
func (t Tool) List(ctx context.Context) ([]ifconfig.Iface, error) {
	out, err := t.ifconfig(ctx, "-a")
	if err != nil {
		return nil, err
	}
	return ifconfig.ParseIfconfig(out), nil
}

// RouteAdd routes a prefix into the interface (route -n add -inet|-inet6 <net> -interface <iface>); a route that
// is there already is not an error.
func (t Tool) RouteAdd(ctx context.Context, iface string, p netip.Prefix) error {
	fam := "-inet"
	if p.Addr().Is6() {
		fam = "-inet6"
	}
	_, err := t.R.Run(ctx, run.Cmd{Name: "route", Args: []string{"-n", "add", fam, p.Masked().String(), "-interface", iface}, Timeout: timeout})
	if ee, ok := run.IsExit(err); ok {
		if strings.Contains(strings.ToLower(ee.Stderr), "file exists") {
			return nil
		}
		return api.Errorf(api.CodeInternal, "route add %s: %s", p.Masked(), firstLine(ee.Stderr))
	}
	return err
}

// DefaultGateways returns the gateways of the host's IPv4 and IPv6 default routes (route -n get), the ones there are.
// UNVERIFIED: the "gateway:" line of route -n get on FreeBSD 15.1.
func (t Tool) DefaultGateways(ctx context.Context) []netip.Addr {
	var out []netip.Addr
	for _, fam := range []string{"-inet", "-inet6"} {
		res, err := t.R.Run(ctx, run.Cmd{Name: "route", Args: []string{"-n", "get", fam, "default"}, Timeout: timeout})
		if err != nil {
			continue
		}
		for _, ln := range strings.Split(string(res.Stdout), "\n") {
			if v, ok := strings.CutPrefix(strings.TrimSpace(ln), "gateway:"); ok {
				if a, err := netip.ParseAddr(strings.TrimSpace(v)); err == nil {
					out = append(out, a.WithZone(""))
				}
			}
		}
	}
	return out
}

// ModuleLoaded reports whether if_wg is loaded (kldstat -q -n if_wg).
func (t Tool) ModuleLoaded(ctx context.Context) bool {
	_, err := t.R.Run(ctx, run.Cmd{Name: "kldstat", Args: []string{"-q", "-n", wireguard.Module}, Timeout: 10 * time.Second})
	return err == nil
}
