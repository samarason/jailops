package priv

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"time"

	"jailops.net/jailops/internal/render"
	"jailops.net/jailops/internal/sys/run"
	"jailops.net/jailops/sdk/api"
)

// DNSUnboundReq is the request of dns.unbound: Apply writes the file and reloads unbound when the file is not what the
// stored objects render; without it the operation only reports.
type DNSUnboundReq struct {
	Apply bool `json:"apply,omitempty"`
}

// UnboundRes says where the names of the jails stand. Enabled is false when priv.conf has no unbound-conf: the
// integration is off and nothing else is set.
type UnboundRes struct {
	Enabled  bool   `json:"enabled"`
	Reason   string `json:"reason,omitempty"` // why it is not enabled although priv.conf allows it: what is missing, with the fix
	Base     bool   `json:"base,omitempty"`   // the file is the default one: the base system's local-unbound answers
	Path     string `json:"path,omitempty"`
	Suffix   string `json:"suffix,omitempty"`   // the zone suffix of the names (dns-suffix)
	Current  bool   `json:"current"`            // the file holds what the stored objects render
	Changed  bool   `json:"changed,omitempty"`  // this call wrote it
	Reloaded bool   `json:"reloaded,omitempty"` // and the resolver read it again
	Control  string `json:"control,omitempty"`  // why the control program did not answer; empty: it did
	Names    int    `json:"names"`              // the distinct names in the file
	Jails    int    `json:"jails,omitempty"`    // the running jails with an address they are for
	Projects int    `json:"projects,omitempty"` // and the projects of those
	// Forward are the upstream resolvers the host's unbound sends every other name to; Recurse says it resolves them
	// itself from the root servers (no forward zone). Both are empty while the control program does not answer.
	Forward  []string `json:"forward,omitempty"`
	Recurse  bool     `json:"recurse,omitempty"`
	Sample   string   `json:"sample,omitempty"`   // "NAME ADDRESS" of one running jail, for a test lookup
	Gateways []string `json:"gateways,omitempty"` // the addresses of the host on the networks the resolver has to listen on
}

var dnsMu sync.Mutex

// DefaultUnboundConf is the file of the base system's local-unbound: local-unbound-setup includes /var/unbound/conf.d/*.conf.
const DefaultUnboundConf = "/var/unbound/conf.d/jailops.conf"

// DefaultDNSSuffix is the zone suffix of the names of the jails: NAME.PROJECT.internal.
const DefaultDNSSuffix = "internal"

// DNSUnbound renders the names of the running jails for the host's resolver and, with Apply, writes them to the one
// file root named (unbound-conf in priv.conf; by default the conf.d of local-unbound) and has the resolver read it
// again. The text is made here, from the stored objects of the jails and networks: the daemon chooses no byte of it,
// so a compromised daemon cannot make the resolver answer for names of its own choosing beyond what a jail's own name
// and addresses say. It is available when the directory of the file exists, belongs to root and is closed to others,
// and the control program of the resolver exists; otherwise Enabled is false and Reason says what to do.
func (l *Local) DNSUnbound(ctx context.Context, apply bool) (UnboundRes, error) {
	res := UnboundRes{}
	path := l.cfg.UnboundConf
	if path == "" {
		return res, nil
	}
	res.Path, res.Base, res.Suffix = path, path == DefaultUnboundConf, l.cfg.DNSSuffix
	if _, err := os.Stat(filepath.Dir(path)); err != nil {
		res.Reason = filepath.Dir(path) + " does not exist (the host resolver is not set up: local-unbound-setup)"
		return res, nil
	}
	if err := rootOwned(filepath.Dir(path)); err != nil {
		d := filepath.Dir(path)
		res.Reason = d + " is not closed to others (" + err.Error() + "): chown root:wheel " + d + " && chmod 755 " + d
		return res, nil
	}
	if _, ok := controlBinary(res.Base); !ok {
		res.Reason = "the control program of the resolver (" + strings.Join(controlNames(res.Base), " or ") + ") is not installed"
		return res, nil
	}
	res.Enabled = true
	if apply && !isAdmin(ctx) {
		return res, forbidden("dns.unbound with apply changes the host's resolver: it needs the admin assertion")
	}
	dnsMu.Lock()
	defer dnsMu.Unlock()
	jails, nets := l.dnsInputs(ctx)
	text := render.UnboundConf(l.cfg.DNSSuffix, jails, nets, listeningAddrs(path))
	res.Names = countNames(text)
	projects := map[string]bool{}
	for _, j := range jails {
		res.Jails++
		projects[j.Project] = true
		if res.Sample == "" && len(j.Addrs) > 0 {
			res.Sample = j.Name + "." + render.UnboundZone(j.Project, l.cfg.DNSSuffix) + " " + j.Addrs[0].String()
		}
	}
	for _, n := range nets {
		if n.Gateway.IsValid() && !slices.Contains(res.Gateways, n.Gateway.String()) {
			res.Gateways = append(res.Gateways, n.Gateway.String())
		}
	}
	res.Projects = len(projects)
	slices.Sort(res.Gateways)
	cur, err := os.ReadFile(path)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return res, fmt.Errorf("unbound-conf %s: %w", path, err)
	}
	res.Current = err == nil && bytes.Equal(cur, []byte(text))
	var out string
	var cerr error
	if apply && !res.Current {
		if err := l.writeUnboundConf(path, text); err != nil {
			return res, err
		}
		// The resolver checks its configuration, with the new file in place, before it reads it: a text it refuses
		// (an interface the administrator has named too) puts the old file back and nothing is reloaded.
		if why := l.checkResolver(ctx, res.Base); why != "" {
			l.restoreUnboundConf(path, cur, err == nil)
			res.Control = "the resolver refused the names, the old file is back: " + why
			return res, nil
		}
		res.Changed, res.Current = true, true
		// An interface line that is new needs the resolver to start again (a reload does not bind a new address): a
		// new network does. Anything else, a jail that starts or stops, is read by a reload.
		if res.Base && interfaces(string(cur)) != interfaces(text) {
			out, cerr = l.restartResolver(ctx)
		} else {
			out, cerr = l.unboundControl(ctx, res.Base, "reload")
		}
		res.Reloaded = cerr == nil
		if cerr != nil {
			// the resolver would not read it: the old file goes back and the resolver reads that
			l.restoreUnboundConf(path, cur, err == nil)
			res.Changed, res.Current = false, false
			if res.Base {
				_, _ = l.restartResolver(ctx)
			} else {
				_, _ = l.unboundControl(ctx, res.Base, "reload")
			}
		}
	} else {
		out, cerr = l.unboundControl(ctx, res.Base, "status")
	}
	if cerr != nil {
		res.Control = describeControl(out, cerr)
	} else if fw, err := l.unboundControl(ctx, res.Base, "list_forwards"); err == nil {
		res.Forward, res.Recurse = parseForwards(fw)
	}
	return res, nil
}

// checkResolver runs the configuration check of the resolver (local-unbound-checkconf for the base system's, else
// unbound-checkconf) on its own configuration, which includes the file as it is now. It returns the first line of
// what the check says when it refuses; "" when it accepts or when there is no check program to ask.
func (l *Local) checkResolver(ctx context.Context, base bool) string {
	names := []string{"unbound-checkconf", "local-unbound-checkconf"}
	if base {
		names = []string{"local-unbound-checkconf"}
	}
	for _, n := range names {
		bin, err := exec.LookPath(n)
		if err != nil {
			continue
		}
		res, err := l.d.Runner.Run(ctx, run.Cmd{Name: bin, Timeout: 20 * time.Second})
		if err == nil {
			return ""
		}
		out := strings.TrimSpace(string(res.Stdout) + "\n" + string(res.Stderr))
		for _, ln := range strings.Split(out, "\n") {
			if ln = strings.TrimSpace(ln); ln != "" {
				if len(ln) > 200 {
					ln = ln[:200]
				}
				return ln
			}
		}
		return err.Error()
	}
	return ""
}

// restoreUnboundConf puts the old text of the file back (or removes the file when there was none).
func (l *Local) restoreUnboundConf(path string, old []byte, existed bool) {
	if existed {
		_ = l.writeUnboundConf(path, string(old))
		return
	}
	_ = os.Remove(path)
}

// interfaces is the interface lines of a file, in a fixed order, to tell whether a reload is enough.
func interfaces(text string) string {
	var out []string
	for _, l := range strings.Split(text, "\n") {
		if f := strings.Fields(l); len(f) == 2 && f[0] == "interface:" {
			out = append(out, f[1])
		}
	}
	slices.Sort(out)
	return strings.Join(out, " ")
}

// restartResolver restarts the base system's local-unbound (a few hundred milliseconds in which the jails get no
// answer): the one case a reload does not do.
func (l *Local) restartResolver(ctx context.Context) (string, error) {
	res, err := l.d.Runner.Run(ctx, run.Cmd{Name: "service", Args: []string{"local_unbound", "restart"}, Timeout: 30 * time.Second})
	return strings.TrimSpace(string(res.Stdout) + " " + string(res.Stderr)), err
}

// dnsInputs reads the running jails and the networks they use from the stored objects. A jail or a network that cannot
// be read is left out: a name that is missing is better than a refusal that stops the others.
func (l *Local) dnsInputs(ctx context.Context) ([]render.DNSJail, []render.DNSNet) {
	list, err := l.d.Jails.List(ctx)
	if err != nil {
		return nil, nil
	}
	var jails []render.DNSJail
	var nets []render.DNSNet
	seen := map[string]bool{}
	for _, j := range list {
		if j.Dying {
			continue
		}
		jn, err := ParseJailName(j.Name)
		if err != nil {
			continue
		}
		rec, err := l.loadRecord(ctx, jn)
		if err != nil {
			continue
		}
		dj := render.DNSJail{Project: jn.Project, Name: jn.Name}
		for _, att := range rec.Spec.Network {
			nw, err := l.loadNetwork(ctx, att.Network)
			if err != nil {
				continue
			}
			for _, raw := range []string{att.IPv4, att.IPv6} {
				if a, err := netip.ParseAddr(raw); err == nil {
					dj.Addrs = append(dj.Addrs, a.Unmap())
				}
			}
			if key := jn.Project + "/" + att.Network; !seen[key] {
				seen[key] = true
				dn := render.DNSNet{Project: jn.Project}
				if v4 := nw.Spec.IPv4; v4 != nil {
					if p, err := netip.ParsePrefix(v4.Subnet); err == nil {
						dn.Subnets = append(dn.Subnets, p)
					}
					if g, err := netip.ParseAddr(v4.Gateway); err == nil {
						dn.Gateway = g
					}
				}
				if v6 := nw.Spec.IPv6; v6 != nil && v6.Mode != api.IPv6None {
					if p, err := netip.ParsePrefix(v6.Subnet); err == nil {
						dn.Subnets = append(dn.Subnets, p)
					}
				}
				nets = append(nets, dn)
			}
		}
		if len(dj.Addrs) > 0 {
			jails = append(jails, dj)
		}
	}
	nets = l.addStoredNetworks(ctx, nets, seen)
	return jails, nets
}

// addStoredNetworks adds every network that a project has, running jail or not: the resolver listens on the host's
// address of each of them and admits their subnets, so that it is there when the first jail of a network starts and
// is restarted when the networks change, never when a jail does.
func (l *Local) addStoredNetworks(ctx context.Context, nets []render.DNSNet, seen map[string]bool) []render.DNSNet {
	owner := map[string]string{} // network name -> project
	pdir := filepath.Join(l.cfg.StateDir, "objects", string(api.KindProject))
	if names, err := l.listState(pdir); err == nil {
		for _, n := range names {
			if !strings.HasSuffix(n, ".json") {
				continue
			}
			b, err := l.readState(filepath.Join(pdir, n))
			if err != nil {
				continue
			}
			var d struct {
				Metadata api.ObjectMeta  `json:"metadata"`
				Spec     api.ProjectSpec `json:"spec"`
			}
			if json.Unmarshal(b, &d) != nil {
				continue
			}
			for _, pn := range d.Spec.Networks {
				owner[pn.Network] = d.Metadata.Name
			}
		}
	}
	ndir := filepath.Join(l.cfg.StateDir, "objects", string(api.KindNetwork))
	names, err := l.listState(ndir)
	if err != nil {
		return nets
	}
	for _, n := range names {
		if !strings.HasSuffix(n, ".json") {
			continue
		}
		b, err := l.readState(filepath.Join(ndir, n))
		if err != nil {
			continue
		}
		var nw networkDoc
		if json.Unmarshal(b, &nw) != nil {
			continue
		}
		project := owner[nw.Metadata.Name]
		if project == "" || seen[project+"/"+nw.Metadata.Name] {
			continue
		}
		seen[project+"/"+nw.Metadata.Name] = true
		dn := render.DNSNet{Project: project}
		if v4 := nw.Spec.IPv4; v4 != nil {
			if p, err := netip.ParsePrefix(v4.Subnet); err == nil {
				dn.Subnets = append(dn.Subnets, p)
			}
			if g, err := netip.ParseAddr(v4.Gateway); err == nil {
				dn.Gateway = g
			}
		}
		if v6 := nw.Spec.IPv6; v6 != nil && v6.Mode != api.IPv6None {
			if p, err := netip.ParsePrefix(v6.Subnet); err == nil {
				dn.Subnets = append(dn.Subnets, p)
			}
		}
		nets = append(nets, dn)
	}
	return nets
}

// writeUnboundConf replaces the file with the text: written beside it, then renamed, so unbound never reads half of it.
// The directory has to be root's and closed to others; a symbolic link or a file of someone else is refused.
func (l *Local) writeUnboundConf(path, text string) error {
	dir := filepath.Dir(path)
	if err := rootOwned(dir); err != nil {
		return fmt.Errorf("unbound-conf: %w", err)
	}
	if _, err := os.Lstat(path); err == nil {
		if err := rootOwned(path); err != nil {
			return fmt.Errorf("unbound-conf: %w", err)
		}
	}
	tmp := filepath.Join(dir, "."+filepath.Base(path)+".tmp")
	f, err := os.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_TRUNC|os.O_EXCL, 0o644)
	if err != nil {
		if errors.Is(err, os.ErrExist) {
			_ = os.Remove(tmp)
			f, err = os.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_TRUNC|os.O_EXCL, 0o644)
		}
		if err != nil {
			return fmt.Errorf("unbound-conf: %w", err)
		}
	}
	_, werr := f.WriteString(text)
	if werr == nil {
		werr = f.Sync()
	}
	if cerr := f.Close(); werr == nil {
		werr = cerr
	}
	if werr != nil {
		_ = os.Remove(tmp)
		return fmt.Errorf("unbound-conf: %w", werr)
	}
	if err := os.Rename(tmp, path); err != nil {
		_ = os.Remove(tmp)
		return fmt.Errorf("unbound-conf: %w", err)
	}
	return nil
}

func controlNames(base bool) []string {
	if base {
		return []string{"local-unbound-control"}
	}
	return []string{"unbound-control", "local-unbound-control"}
}

// controlBinary finds the control program: the one of local-unbound for the default file, else the one of the
// unbound package, else the base system's.
func controlBinary(base bool) (string, bool) {
	for _, n := range controlNames(base) {
		if p, err := exec.LookPath(n); err == nil {
			return p, true
		}
	}
	return "", false
}

// unboundControl runs the control program with one fixed word (reload or status).
func (l *Local) unboundControl(ctx context.Context, base bool, word string) (string, error) {
	var out string
	var err error
	for _, bin := range controlNames(base) {
		var res run.Result
		res, err = l.d.Runner.Run(ctx, run.Cmd{Name: bin, Args: []string{word}, Timeout: 10 * time.Second})
		out = strings.TrimSpace(string(res.Stdout) + " " + string(res.Stderr))
		var ee *run.ExitError
		if err == nil || errors.As(err, &ee) {
			return out, err // it ran: its answer is the answer
		}
	}
	return out, err
}

func describeControl(out string, err error) string {
	s := strings.TrimSpace(out)
	if s == "" {
		s = err.Error()
	}
	if len(s) > 200 {
		s = s[:200]
	}
	return s
}

// listeningAddrs are the addresses the resolver's own configuration (the .conf files next to and below the file the
// helper writes, except that file) already has `interface:` lines for: unbound refuses an address named twice, so the
// generated file leaves them out. "0.0.0.0" stands for every IPv4 address.
func listeningAddrs(own string) []string {
	dir := filepath.Dir(own)
	var files []string
	for _, pat := range []string{filepath.Join(filepath.Dir(dir), "*.conf"), filepath.Join(dir, "*.conf")} {
		m, _ := filepath.Glob(pat)
		files = append(files, m...)
	}
	var out []string
	for _, f := range files {
		if f == own {
			continue
		}
		b, err := os.ReadFile(f)
		if err != nil {
			continue
		}
		for _, l := range strings.Split(string(b), "\n") {
			l = strings.TrimSpace(l)
			if !strings.HasPrefix(l, "interface:") {
				continue
			}
			a := strings.Trim(strings.TrimSpace(strings.TrimPrefix(l, "interface:")), `"`)
			if i := strings.IndexByte(a, '@'); i >= 0 {
				a = a[:i]
			}
			if p, err := netip.ParseAddr(a); err == nil {
				out = append(out, p.String())
			}
		}
	}
	return out
}

// countNames is the number of distinct names the generated text answers.
func countNames(text string) int {
	seen := map[string]bool{}
	for _, l := range strings.Split(text, "\n") {
		if f := strings.Fields(l); len(f) > 1 && f[0] == "local-data:" {
			seen[strings.Trim(f[1], `"`)] = true
		}
	}
	return len(seen)
}

// parseForwards reads the output of `unbound-control list_forwards` (one line per forward zone: `. IN forward ADDR
// ...`): the addresses the root zone is forwarded to, or recurse when it is not forwarded at all.
func parseForwards(out string) ([]string, bool) {
	for _, l := range strings.Split(out, "\n") {
		f := strings.Fields(l)
		if len(f) >= 4 && f[0] == "." && f[2] == "forward" {
			var addrs []string
			for _, a := range f[3:] {
				if p, err := netip.ParseAddr(strings.SplitN(a, "@", 2)[0]); err == nil {
					addrs = append(addrs, p.String())
				}
			}
			return addrs, false
		}
	}
	return nil, true
}
