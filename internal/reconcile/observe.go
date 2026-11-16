package reconcile

import (
	"context"
	"net/netip"

	"jailops.net/jailops/internal/render"
	"jailops.net/jailops/internal/sys/ifconfig"
	"jailops.net/jailops/internal/sys/jailos"
)

// Observed is what the system looks like right now.
type Observed struct {
	Ifaces  map[string]ifconfig.Iface
	Running map[string]jailos.Jail
	// Routes is the routing table; nil when it cannot be read (a route is then neither found nor missing).
	Routes []ifconfig.RouteEntry
}

// HasRoute reports whether the routing table has a route for dest through iface ("" matches any interface), and,
// when reject is set, whether it is a reject route.
func (o *Observed) HasRoute(dest netip.Prefix, iface string, reject bool) bool {
	for _, r := range o.Routes {
		if r.Dest == dest.Masked() && (iface == "" || r.Iface == iface) && r.Reject() == reject {
			return true
		}
	}
	return false
}

// Observe reads interfaces and running jails.
func Observe(ctx context.Context, n ifconfig.Client, j jailos.Observer) (*Observed, error) {
	o := &Observed{Ifaces: map[string]ifconfig.Iface{}, Running: map[string]jailos.Jail{}}
	if n != nil {
		ifs, err := n.List(ctx)
		if err != nil {
			return nil, err
		}
		for _, i := range ifs {
			o.Ifaces[i.Name] = i
		}
	}
	if j != nil {
		js, err := j.List(ctx)
		if err != nil {
			return nil, err
		}
		for _, x := range js {
			if !x.Dying {
				o.Running[x.Name] = x
			}
		}
	}
	return o, nil
}

// ownedBy reports whether an interface whose name the network or jail derives may be treated as its own (see
// render.OwnsIface): the wanted text, or the bare marker of an interface just made.
func ownedBy(i ifconfig.Iface, steps []render.Step) bool {
	return render.OwnsIface(i.Description, WantDesc(steps, i.Name))
}

// WantDesc returns the description the steps give iface, "" when they give none.
func WantDesc(steps []render.Step, iface string) string {
	for _, s := range steps {
		if s.Op == render.OpSetDescription && s.Iface == iface && s.Arg != "" {
			return s.Arg
		}
	}
	return ""
}

// ours reports whether the description is one JailOps writes, in either format.
func ours(i ifconfig.Iface) bool { return render.IsJailOpsDesc(i.Description) }
