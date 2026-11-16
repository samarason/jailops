package render

import (
	"net/netip"
	"slices"
	"strings"
)

// DNSJail is a running jail with the addresses of its attachments, for the names that the host's unbound answers.
type DNSJail struct {
	Project, Name string
	Addrs         []netip.Addr
}

// DNSNet is a network of a project with its subnets and the address of the host on it (the gateway).
type DNSNet struct {
	Project string
	Subnets []netip.Prefix
	Gateway netip.Addr
}

// UnboundZone is the zone of the names inside a project: NAME.<project>.<suffix>; the suffix is `internal` unless
// the administrator sets another (`.internal` is reserved for private use; `.local` is multicast DNS).
func UnboundZone(project, suffix string) string { return project + "." + suffix }

// UnboundConf renders the file that the administrator includes in unbound.conf: for each project with a running jail
// a view that holds the names of the project (and host.<project>.internal, the host on its network) and is given to
// the subnets of the project's networks, so that a jail sees the names of its own project and of no other. The text
// depends on nothing but the arguments, in a fixed order. listening are the addresses the resolver already listens on
// by the administrator's own configuration (an `interface:` line twice is a fatal error of unbound, so none is written
// twice; 0.0.0.0 covers every IPv4 address). A project name and a jail name are DNS labels already
// (lower case letters, digits and hyphens), so nothing needs escaping.
func UnboundConf(suffix string, jails []DNSJail, nets []DNSNet, listening []string) string {
	var b builder
	b.line("%s", Header)
	b.line("# The names of the running jails inside their project, for the unbound of the host (docs/dns.md).")
	byProject := map[string][]DNSJail{}
	for _, j := range jails {
		byProject[j.Project] = append(byProject[j.Project], j)
	}
	projects := make([]string, 0, len(byProject))
	for p := range byProject {
		projects = append(projects, p)
	}
	slices.Sort(projects)
	var acl []string
	for _, p := range projects {
		view := "jailops-" + p
		zone := UnboundZone(p, suffix)
		b.line("view:")
		b.line("\tname: %q", view)
		b.line("\tview-first: yes")
		b.line("\tlocal-zone: %q static", zone+".")
		var recs []string
		for _, n := range nets {
			if n.Project == p && n.Gateway.IsValid() && n.Gateway.Is4() {
				recs = append(recs, unboundNames("host", zone, []netip.Addr{n.Gateway})...)
			}
		}
		js := byProject[p]
		slices.SortFunc(js, func(a, c DNSJail) int { return strings.Compare(a.Name, c.Name) })
		for _, j := range js {
			recs = append(recs, unboundNames(j.Name, zone, j.Addrs)...)
		}
		slices.Sort(recs)
		for _, r := range slices.Compact(recs) {
			b.line("\tlocal-data: %q", r)
		}
		var subs []string
		for _, n := range nets {
			if n.Project != p {
				continue
			}
			for _, s := range n.Subnets {
				subs = append(subs, s.Masked().String())
			}
		}
		slices.Sort(subs)
		for _, s := range slices.Compact(subs) {
			acl = append(acl, "\taccess-control: "+s+" allow")
			acl = append(acl, "\taccess-control-view: "+s+" "+`"`+view+`"`)
		}
	}
	// The server clause carries what unbound needs to answer the jails, so that the administrator adds nothing: it
	// listens on the host's address on EVERY network of a project, running jail or not (so the resolver is there
	// when the first jail of a network starts and is restarted only when the networks change, never when a jail
	// does), but not on an address the administrator's own configuration lists already; it may bind the address
	// before the network exists, and admits the subnets of all the projects (a project without a running jail has
	// no view: its subnets are admitted and see the common names only).
	var ifaces, extra []string
	for _, n := range nets {
		if n.Gateway.IsValid() && n.Gateway.Is4() && n.Project != "" && !slices.Contains(listening, n.Gateway.String()) && !slices.Contains(listening, "0.0.0.0") {
			ifaces = append(ifaces, n.Gateway.String())
		}
		if _, ok := byProject[n.Project]; !ok && n.Project != "" {
			for _, sn := range n.Subnets {
				extra = append(extra, "\taccess-control: "+sn.Masked().String()+" allow")
			}
		}
	}
	slices.Sort(extra)
	acl = append(acl, slices.Compact(extra)...)
	slices.Sort(ifaces)
	b.line("server:")
	if len(ifaces) > 0 {
		for _, a := range slices.Compact(ifaces) {
			b.line("\tinterface: %s", a)
		}
		b.line("\tip-transparent: yes")
	}
	for _, l := range acl {
		b.line("%s", l)
	}
	s, _ := b.result()
	return s
}

func unboundRecord(name string, a netip.Addr) string {
	t := "A"
	if a.Is6() {
		t = "AAAA"
	}
	return name + ". " + t + " " + a.String()
}

// unboundNames are the records of one name inside a zone, in the three forms: NAME with every address, NAME.v4 with the
// IPv4 ones and NAME.v6 with the IPv6 ones; a form with no address of its family is not made.
func unboundNames(name, zone string, addrs []netip.Addr) []string {
	var v4, v6 []netip.Addr
	for _, a := range addrs {
		if a.Is4() {
			v4 = append(v4, a)
		} else if a.IsValid() {
			v6 = append(v6, a)
		}
	}
	var out []string
	for _, a := range addrs {
		if a.IsValid() {
			out = append(out, unboundRecord(name+"."+zone, a))
		}
	}
	for _, a := range v4 {
		out = append(out, unboundRecord(name+".v4."+zone, a))
	}
	for _, a := range v6 {
		out = append(out, unboundRecord(name+".v6."+zone, a))
	}
	return out
}
