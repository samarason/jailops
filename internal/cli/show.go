package cli

import (
	"fmt"
	"io"
	"strconv"
	"strings"

	"jailops.net/jailops/sdk/api"
)

// The human forms of 'show' for the host resources: a title line, the settings as aligned key: value lines with
// sizes in units, and the problems the server reports. -o yaml and -o json print the whole object.

type showWriter struct {
	w     io.Writer
	width int
}

func (s showWriter) title(f string, a ...any) { fprintf(s.w, f+"\n", a...) }

func (s showWriter) kv(k, v string) {
	fprintf(s.w, "  %-*s %s\n", s.width, k+":", v)
}

func (s showWriter) section(t string) { fprintf(s.w, "\n%s\n", t) }

// labels writes the labels line when there are any.
func (s showWriter) labels(m api.ObjectMeta) {
	if len(m.Labels) == 0 {
		return
	}
	var l []string
	for _, k := range sortedKeys(m.Labels) {
		l = append(l, k+"="+m.Labels[k])
	}
	s.kv("Labels", strings.Join(l, ", "))
}

// problems writes the conditions that are not true, the way 'jail info' does.
func (s showWriter) problems(conds []api.Condition) {
	var out []string
	for _, c := range conds {
		if c.Status == api.ConditionTrue {
			continue
		}
		p := c.Type
		if c.Reason != "" {
			p += " " + c.Reason
		}
		if c.Message != "" {
			p += ": " + c.Message
		}
		out = append(out, p)
	}
	if len(out) == 0 {
		return
	}
	s.section("Problems")
	for _, p := range out {
		fprintf(s.w, "  %s\n", p)
	}
}

func orText(s, none string) string {
	if s == "" {
		return none
	}
	return s
}

func (a *app) showStorage(st api.Storage) error {
	s := showWriter{w: a.env.Stdout, width: 13}
	s.title("Storage %s", st.Metadata.Name)
	s.kv("Dataset", st.Spec.Dataset)
	if st.Spec.Comment != "" {
		s.kv("Comment", st.Spec.Comment)
	}
	s.kv("Compression", orText(st.Spec.Compression, "inherited"))
	pool := dash(st.Status.Pool)
	if st.Status.Health != "" {
		pool += " (" + st.Status.Health + ")"
	}
	s.kv("Pool", pool)
	if st.Status.Size > 0 {
		s.kv("Size", humanBytes(st.Status.Size))
	}
	s.kv("Used", humanBytes(st.Status.Used))
	s.kv("Available", humanBytes(st.Status.Available))
	if st.Status.Fragmentation > 0 {
		s.kv("Fragmented", strconv.Itoa(st.Status.Fragmentation)+"%")
	}
	s.kv("Age", age(a.env.Now(), st.Metadata.CreatedAt))
	s.labels(st.Metadata)
	s.problems(st.Status.Conditions)
	return nil
}

// showAddressSet lists the members of a set, each with its comment: what a reviewer of a firewall wants to read next to
// "set:office" in a rule. A member that is a jail or a set says so in the comment column when it has none.
func (a *app) showAddressSet(set api.AddressSet) error {
	s := showWriter{w: a.env.Stdout, width: 9}
	s.title("Address set %s", set.Metadata.Name)
	if set.Spec.Comment != "" {
		s.kv("Comment", set.Spec.Comment)
	}
	s.kv("Age", age(a.env.Now(), set.Metadata.CreatedAt))
	s.labels(set.Metadata)
	rows := make([][]string, 0, len(set.Spec.Addresses))
	for _, e := range set.Spec.Addresses {
		c := e.Comment
		if c == "" {
			switch {
			case strings.HasPrefix(e.Address, "jail:"):
				c = "(a jail of the project)"
			case strings.HasPrefix(e.Address, "set:"):
				c = "(an address set of the project)"
			}
		}
		rows = append(rows, []string{e.Address, orText(c, "-")})
	}
	if len(rows) > 0 {
		fprintln(a.env.Stdout)
		a.printTable(a.env.Stdout, []string{"MEMBER", "COMMENT"}, rows, nil)
	}
	return nil
}

// ruleText writes a rule the way --rule reads it, without its name and comment.
func ruleText(r api.FirewallRule) string {
	t := []string{r.Action, r.Direction}
	if r.Proto != "" {
		t = append(t, r.Proto)
	}
	if len(r.From) > 0 {
		t = append(t, "from", strings.Join(r.From, ","))
	}
	if len(r.To) > 0 {
		t = append(t, "to", strings.Join(r.To, ","))
	}
	if len(r.Ports) > 0 {
		t = append(t, "port", strings.Join(r.Ports, ","))
	}
	if r.Log {
		t = append(t, "log")
	}
	if r.Redirect != nil {
		t = append(t, fmt.Sprintf("rdr %d:%d", r.Redirect.HostPort, r.Redirect.JailPort))
	}
	if r.Disabled {
		t = append(t, "disabled")
	}
	return strings.Join(t, " ")
}

// showPolicy lists a policy with what it is for and every rule with why it is there: what a reviewer of the firewall reads.
func (a *app) showPolicy(p api.FirewallPolicy) error {
	s := showWriter{w: a.env.Stdout, width: 13}
	s.title("Firewall policy %s", p.Metadata.Name)
	if p.Spec.Comment != "" {
		s.kv("Comment", p.Spec.Comment)
	}
	s.kv("Default in", p.Spec.DefaultIn)
	s.kv("Default out", p.Spec.DefaultOut)
	s.kv("Age", age(a.env.Now(), p.Metadata.CreatedAt))
	s.labels(p.Metadata)
	if len(p.Spec.Rules) > 0 {
		rows := make([][]string, 0, len(p.Spec.Rules))
		for i, r := range p.Spec.Rules {
			why := r.Comment
			if r.Name != "" {
				why = strings.TrimSpace(r.Name + ": " + why)
			}
			rows = append(rows, []string{strconv.Itoa(i + 1), ruleText(r), orText(why, "-")})
		}
		fprintln(a.env.Stdout)
		a.printTable(a.env.Stdout, []string{"#", "RULE", "COMMENT"}, rows, nil)
	}
	if p.Spec.Raw != "" {
		s.section("A raw PF fragment is part of this policy (admin): jailops firewall policy show -o yaml")
	}
	return nil
}

func (a *app) showNetwork(n api.Network) error {
	s := showWriter{w: a.env.Stdout, width: 11}
	s.title("Network %s", n.Metadata.Name)
	s.kv("Uplink", orText(n.Spec.Uplink, "none"))
	if v4 := n.Spec.IPv4; v4 != nil {
		line := v4.Subnet + ", gateway " + v4.Gateway
		if v4.NAT {
			line += ", NAT"
		}
		s.kv("IPv4", line)
		rng := v4.Range
		if len(v4.Exclude) > 0 {
			rng += " (except " + strings.Join(v4.Exclude, ", ") + ")"
		}
		s.kv("IPv4 range", rng)
	} else {
		s.kv("IPv4", "none")
	}
	if v6 := n.Spec.IPv6; v6 != nil && v6.Mode != api.IPv6None {
		s.kv("IPv6", fmt.Sprintf("%s (%s), gateway fe80::1", v6.Subnet, v6.Mode))
		rng := v6.Range
		if len(v6.Exclude) > 0 {
			rng += " (except " + strings.Join(v6.Exclude, ", ") + ")"
		}
		s.kv("IPv6 range", rng)
	} else {
		s.kv("IPv6", "none")
	}
	switch d := n.Status.DNS; {
	case d == nil:
		if len(n.Spec.DNS) > 0 {
			s.kv("DNS", strings.Join(n.Spec.DNS, ", "))
		}
	case d.Source == api.DNSFromNetwork:
		s.kv("DNS", strings.Join(d.Nameservers, ", "))
	case d.Source == api.DNSFromHost:
		s.kv("DNS", strings.Join(d.Nameservers, ", ")+" (the host's nameservers)")
	case d.Source == api.DNSFromGateway:
		s.kv("DNS", strings.Join(d.Nameservers, ", ")+" (the gateway: the host resolves only through loopback)")
		if d.Advice != "" {
			s.kv("Note", d.Advice)
		}
	default:
		s.kv("DNS", "none: jails get no nameserver (jailops doctor says why)")
	}
	if n.Spec.MTU > 0 {
		s.kv("MTU", strconv.Itoa(n.Spec.MTU))
	}
	s.kv("Addresses", fmt.Sprintf("%d used, %d free", n.Status.Allocated, n.Status.Free))
	if len(n.Status.Links) > 0 {
		s.kv("Links", strings.Join(n.Status.Links, ", ")+" (the host ends of the running jails' interfaces)")
	}
	if len(n.Status.Orphans) > 0 {
		s.kv("Orphans", strings.Join(n.Status.Orphans, ", ")+" (interfaces without a jail)")
	}
	s.kv("Age", age(a.env.Now(), n.Metadata.CreatedAt))
	s.labels(n.Metadata)
	s.problems(n.Status.Conditions)
	return nil
}

func (a *app) showImage(i api.Image) error {
	s := showWriter{w: a.env.Stdout, width: 10}
	now := a.env.Now()
	s.title("Image %s", i.Metadata.Name)
	s.kv("System", fmt.Sprintf("%s %s (%s)", i.Spec.OS, i.Spec.Release, dash(i.Spec.Arch)))
	src := i.Spec.Source.Type
	if i.Spec.Source.Repo != "" {
		src += " from " + i.Spec.Source.Repo
	}
	if len(i.Spec.Source.Sets) > 0 {
		src += ", sets " + strings.Join(i.Spec.Source.Sets, ", ")
	}
	s.kv("Source", src)
	var aliases []string
	for _, al := range i.Spec.Aliases {
		if g, ok := i.Status.Aliases[al]; ok {
			aliases = append(aliases, fmt.Sprintf("%s -> g%d", al, g))
		} else {
			aliases = append(aliases, al+" (no generation yet)")
		}
	}
	s.kv("Aliases", orText(strings.Join(aliases, ", "), "none"))
	var keep []string
	if r := i.Spec.Retention; r.KeepLast > 0 {
		keep = append(keep, "the last "+strconv.Itoa(r.KeepLast))
	}
	if r := i.Spec.Retention; r.KeepDays > 0 {
		keep = append(keep, "unused ones for "+strconv.Itoa(r.KeepDays)+" days")
	}
	s.kv("Keeps", orText(strings.Join(keep, ", "), "every generation"))
	s.kv("Age", age(now, i.Metadata.CreatedAt))
	s.labels(i.Metadata)
	a.showAutoUpgrade(s, i)
	s.section("Generations")
	if len(i.Status.Generations) == 0 {
		fprintf(s.w, "  none: build one with 'jailops image build %s'\n", i.Metadata.Name)
		return nil
	}
	rows := [][]string{}
	for _, g := range i.Status.Generations {
		pkgs := "-"
		if g.Packages > 0 {
			pkgs = strconv.Itoa(g.Packages)
		}
		rows = append(rows, []string{fmt.Sprintf("g%d", g.Number), dash(g.FreeBSDVersion), pkgs, age(now, g.CreatedAt), joinOrDash(g.Refs)})
	}
	a.printTable(indentWriter{s.w}, []string{"GEN", "FREEBSD", "PACKAGES", "AGE", "USED BY"}, rows, nil)
	return nil
}

func (a *app) showProject(p api.Project) error {
	s := showWriter{w: a.env.Stdout, width: 12}
	s.title("Project %s", p.Metadata.Name)
	if p.Spec.Comment != "" {
		s.kv("Comment", p.Spec.Comment)
	}
	s.kv("Hosts", orText(strings.Join(p.Spec.Hosts, ", "), "this host"))
	var nets, stor []string
	for _, n := range p.Spec.Networks {
		nets = append(nets, n.Network)
	}
	for _, st := range p.Spec.Storage {
		g := st.Storage
		if st.Storage == "*" {
			g = "every storage"
		}
		if st.Quota != "" {
			g += " (quota " + sizeText(st.Quota) + ")"
		}
		stor = append(stor, g)
	}
	s.kv("Networks", orText(strings.Join(nets, ", "), "none: grant one with 'jailops network grant NETWORK --project "+p.Metadata.Name+"'"))
	s.kv("Storage", orText(strings.Join(stor, ", "), "none: grant one with 'jailops storage grant NAME --project "+p.Metadata.Name+"'"))
	s.kv("Firewall", orText(strings.Join(p.Spec.FirewallPolicies, ", "), "none"))
	s.kv("Images", orText(strings.Join(p.Spec.Images, ", "), "any"))
	s.kv("Age", age(a.env.Now(), p.Metadata.CreatedAt))
	s.labels(p.Metadata)
	q, st := p.Spec.Quotas, p.Status
	limit := func(n int) string {
		if n <= 0 {
			return "(no quota)"
		}
		return "of " + strconv.Itoa(n)
	}
	s.section("Usage")
	s.kv("Jails", strconv.Itoa(st.Jails)+" "+limit(q.Jails))
	s.kv("CPU", strconv.Itoa(st.CPU)+" cores "+limit(q.CPU))
	mem := humanBytes(st.MemoryUsed)
	if q.Memory != "" {
		mem += " of " + sizeText(q.Memory)
	} else {
		mem += " (no quota)"
	}
	s.kv("Memory", mem)
	s.kv("Disk", humanBytes(st.DiskUsed))
	s.kv("Addresses", strconv.Itoa(st.Addresses)+" "+limit(q.Addresses))
	if q.PIDs > 0 {
		s.kv("Processes", "quota "+strconv.Itoa(q.PIDs))
	}
	s.problems(st.Conditions)
	return nil
}

// indentWriter indents every line written through it by two spaces.
type indentWriter struct{ w io.Writer }

func (i indentWriter) Write(b []byte) (int, error) {
	lines := strings.SplitAfter(string(b), "\n")
	for _, l := range lines {
		if l == "" {
			continue
		}
		if _, err := io.WriteString(i.w, "  "+l); err != nil {
			return 0, err
		}
	}
	return len(b), nil
}

// showAutoUpgrade prints the automatic upgrade of an image: the setting, the next run and the latest runs.
func (a *app) showAutoUpgrade(s showWriter, i api.Image) {
	au, st := i.Spec.AutoUpgrade, i.Status.AutoUpgrade
	if (au == nil || !au.Enabled) && st == nil {
		s.kv("Nightly", "off ('jailops image set "+i.Metadata.Name+" --auto-upgrade' turns it on)")
		return
	}
	if au == nil || !au.Enabled {
		s.kv("Nightly", "off")
	} else {
		at := au.At
		if at == "" {
			at = api.DefaultAutoUpgradeAt
		}
		what := "generation and jails"
		if au.Packages {
			what += " and their packages"
		}
		line := "every night at " + at + ": " + what
		if st != nil && !st.Next.IsZero() {
			line += "; next " + st.Next.Local().Format("2006-01-02 15:04")
		}
		s.kv("Nightly", line)
	}
	if st == nil || len(st.Recent) == 0 {
		return
	}
	s.section("Automatic upgrades")
	rows := [][]string{}
	for _, r := range st.Recent {
		what := fmt.Sprintf("%d moved, %d packages upgraded", r.JailsMoved, r.JailsUpgraded)
		if r.Generation != "" {
			what = r.Generation + ", " + what
		}
		if r.Detail != "" {
			what += "; " + r.Detail
		}
		rows = append(rows, []string{r.Started.Local().Format("2006-01-02 15:04"), r.Result, what})
	}
	a.printTable(indentWriter{s.w}, []string{"STARTED", "RESULT", "WHAT"}, rows, nil)
}
