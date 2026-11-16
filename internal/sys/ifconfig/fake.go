package ifconfig

import (
	"context"
	"net/netip"
	"sort"
	"strconv"
	"strings"
	"sync"

	"jailops.net/jailops/internal/ipam"
	"jailops.net/jailops/sdk/api"
)

type fakeIf struct {
	Iface
	jail string // non-empty: lives in that jail's vnet
	peer string // epair peer
}

// Fake is an in-memory interface table with the same name rules as Command.
type Fake struct {
	mu        sync.Mutex
	o         Options
	ifs       map[string]*fakeIf
	routes    map[string]bool
	nextEpair int
	// Forwarding is the value IPv6Forwarding returns.
	Forwarding bool
}

var (
	_ Client = (*Fake)(nil)
	_ Reader = (*Fake)(nil)
)

// NewFake returns a Fake with a loopback interface.
func NewFake(o Options) *Fake {
	f := &Fake{o: o, ifs: map[string]*fakeIf{}, routes: map[string]bool{}}
	f.ifs["lo0"] = &fakeIf{Iface: Iface{Name: "lo0", Flags: []string{"UP", "LOOPBACK", "RUNNING"}, MTU: 16384}}
	return f
}

// AddForeign inserts an interface JailOps does not own (test helper): no description, and no group of a kind JailOps
// creates unless the name is an epair's (epair0a), or a bridge's (bridge0: in the group, but never owned).
func (f *Fake) AddForeign(name string, up bool) {
	i := Iface{Name: name, MTU: 1500}
	switch drv, _ := ipam.DriverLikeName(name); drv {
	case "bridge", "epair":
		i.Groups = []string{drv}
	}
	if up {
		i.Flags = []string{"UP"}
	}
	f.AddIface(i)
}

// AddIface inserts an interface as the kernel would show it (test helper): a bridge made by hand (Groups "bridge"),
// one without a description, or one with a forged description.
func (f *Fake) AddIface(i Iface) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.ifs[i.Name] = &fakeIf{Iface: i}
}

// AddToJail inserts an interface into the vnet of jail (test helper).
func (f *Fake) AddToJail(jail string, i Iface) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.ifs[i.Name] = &fakeIf{Iface: i, jail: jail}
}

// Show implements Reader.
func (f *Fake) Show(_ context.Context, name string) (Iface, error) {
	if err := ValidateIfName(name); err != nil {
		return Iface{}, err
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	i, err := f.get(name)
	if err != nil {
		return Iface{}, err
	}
	return i.copy(), nil
}

// ShowInJail implements Reader.
func (f *Fake) ShowInJail(_ context.Context, jail, name string) (Iface, error) {
	if err := ValidateIfName(name); err != nil {
		return Iface{}, err
	}
	if err := ValidateJailRef(jail); err != nil {
		return Iface{}, err
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	i := f.ifs[name]
	if i == nil || i.jail != jail {
		return Iface{}, notFound(name)
	}
	return i.copy(), nil
}

func (i *fakeIf) copy() Iface {
	c := i.Iface
	c.Flags = append([]string(nil), c.Flags...)
	c.Groups = append([]string(nil), c.Groups...)
	c.Members = append([]Member(nil), c.Members...)
	c.Inet = append([]netip.Prefix(nil), c.Inet...)
	c.Inet6 = append([]netip.Prefix(nil), c.Inet6...)
	return c
}

// own checks, as Command does in the kernel, that JailOps owns every name. f.mu must be held.
func (f *Fake) ownLocked(names ...string) error {
	for _, n := range names {
		if err := ValidateIfName(n); err != nil {
			return err
		}
	}
	for _, n := range names {
		i, err := f.get(n)
		if err != nil {
			return err
		}
		if err := f.o.Owns(i.Iface); err != nil {
			return err
		}
	}
	return nil
}

// AddHost inserts an interface of the host that JailOps does not own, with its addresses and groups (test helper).
func (f *Fake) AddHost(i Iface) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if i.MTU == 0 {
		i.MTU = 1500
	}
	f.ifs[i.Name] = &fakeIf{Iface: i}
}

// Routes returns the installed routes as "-inet dest gw" strings.
func (f *Fake) Routes() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	var r []string
	for k := range f.routes {
		r = append(r, strings.TrimSpace(k))
	}
	sort.Strings(r)
	return r
}

func notFound(n string) error {
	return api.Errorf(api.CodeNotFound, "ifconfig: interface %s does not exist", n)
}

// get returns a host-visible interface.
func (f *Fake) get(n string) (*fakeIf, error) {
	i := f.ifs[n]
	if i == nil || i.jail != "" {
		return nil, notFound(n)
	}
	return i, nil
}

// List implements Client. Interfaces moved into a jail are not listed.
func (f *Fake) List(context.Context) ([]Iface, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	var out []Iface
	for _, i := range f.ifs {
		if i.jail == "" {
			out = append(out, i.copy())
		}
	}
	sort.Slice(out, func(a, b int) bool { return out[a].Name < out[b].Name })
	return out, nil
}

// SetDescription implements Client.
func (f *Fake) SetDescription(_ context.Context, iface, desc string) error {
	desc = descOrMarker(desc)
	if err := ValidateDescription(desc); err != nil {
		return err
	}
	if !HasMarker(desc) {
		return api.Errorf(api.CodeInvalid, "description %q would remove the JailOps marker (\"jailops ...\")", desc)
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if err := f.ownLocked(iface); err != nil {
		return err
	}
	i, _ := f.get(iface)
	i.Description = desc
	return nil
}

// EpairCreate implements Client.
func (f *Fake) EpairCreate(_ context.Context, name string) (string, string, error) {
	a, b := name+"a", name+"b"
	for _, n := range []string{a, b} {
		if err := CheckNewName(n); err != nil {
			return "", "", err
		}
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.ifs[a] != nil || f.ifs[b] != nil {
		return "", "", api.Errorf(api.CodeAlreadyExists, "ifconfig: interface %s already exists", a)
	}
	f.nextEpair++
	for _, n := range []string{a, b} {
		f.ifs[n] = &fakeIf{Iface: Iface{Name: n, MTU: 1500, Flags: []string{"BROADCAST", "MULTICAST"}, Groups: []string{"epair"}, Description: Marker,
			MAC: "02:00:00:00:00:" + strconv.FormatInt(int64(0x10+f.nextEpair), 16)}}
	}
	f.ifs[a].peer, f.ifs[b].peer = b, a
	return a, b, nil
}

// EpairDestroy implements Client.
func (f *Fake) EpairDestroy(_ context.Context, iface string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if err := f.ownLocked(iface); err != nil {
		return err
	}
	i, _ := f.get(iface)
	if i.peer == "" {
		return api.Errorf(api.CodeInvalid, "ifconfig: %s is not an epair", iface)
	}
	f.removeLocked(i.peer)
	f.removeLocked(iface)
	return nil
}

func (f *Fake) removeLocked(n string) {
	delete(f.ifs, n)
	for _, i := range f.ifs {
		for k, m := range i.Members {
			if m.Name == n {
				i.Members = append(i.Members[:k], i.Members[k+1:]...)
				break
			}
		}
	}
}

// MoveToJail implements Client.
func (f *Fake) MoveToJail(_ context.Context, iface, jail string) error {
	if err := ValidateJailRef(jail); err != nil {
		return err
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if err := f.ownLocked(iface); err != nil {
		return err
	}
	i, _ := f.get(iface)
	for _, b := range f.ifs {
		for k, m := range b.Members {
			if m.Name == iface {
				b.Members = append(b.Members[:k], b.Members[k+1:]...)
				break
			}
		}
	}
	i.jail = jail
	return nil
}

// MoveFromJail implements Client.
func (f *Fake) MoveFromJail(_ context.Context, iface, jail string) error {
	if err := ValidateIfName(iface); err != nil {
		return err
	}
	if err := ValidateJailRef(jail); err != nil {
		return err
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	i := f.ifs[iface]
	if i == nil || i.jail != jail {
		return notFound(iface)
	}
	if err := f.o.Owns(i.Iface); err != nil {
		return err
	}
	i.jail = ""
	return nil
}

// SetLink implements Client.
func (f *Fake) SetLink(_ context.Context, iface string, up bool) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if err := f.ownLocked(iface); err != nil {
		return err
	}
	i, _ := f.get(iface)
	var fl []string
	for _, x := range i.Flags {
		if x != "UP" {
			fl = append(fl, x)
		}
	}
	if up {
		fl = append([]string{"UP"}, fl...)
	}
	i.Flags = fl
	return nil
}

func (f *Fake) addr(iface string, p netip.Prefix, add bool) error {
	if err := validPrefix(p); err != nil {
		return err
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if err := f.ownLocked(iface); err != nil {
		return err
	}
	i, _ := f.get(iface)
	l := &i.Inet
	if p.Addr().Is6() {
		l = &i.Inet6
	}
	for k, x := range *l {
		if x == p {
			if add {
				return api.Errorf(api.CodeAlreadyExists, "ifconfig: address %s already assigned", p)
			}
			*l = append((*l)[:k], (*l)[k+1:]...)
			return nil
		}
	}
	if add {
		// the kernel does not take the same IPv4 address on a second interface when the subnets overlap (a /32 beside
		// a /32 is fine, a /32 beside the /24 of a gateway is "File exists")
		if !p.Addr().Is6() {
			for n, o := range f.ifs {
				if n == iface {
					continue
				}
				for _, x := range o.Inet {
					if x.Addr() == p.Addr() && (x.Bits() < 32 || p.Bits() < 32) {
						return api.Errorf(api.CodeAlreadyExists, "ifconfig: ioctl (SIOCAIFADDR): File exists (%s is on %s)", p.Addr(), n)
					}
				}
			}
		}
		*l = append(*l, p)
		return nil
	}
	return api.Errorf(api.CodeNotFound, "ifconfig: address %s not assigned", p)
}

// AddrAdd implements Client.
func (f *Fake) AddrAdd(_ context.Context, iface string, p netip.Prefix) error {
	return f.addr(iface, p, true)
}

// AddrRemove implements Client.
func (f *Fake) AddrRemove(_ context.Context, iface string, p netip.Prefix) error {
	return f.addr(iface, p, false)
}

func (f *Fake) route(r Route, add bool) error {
	a, err := routeArgs(r, false)
	if err != nil {
		return err
	}
	key := ""
	for _, x := range a {
		key += x + " "
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if r.Interface != "" && r.Gateway == "" {
		if err := f.ownLocked(r.Interface); err != nil {
			return err
		}
	}
	if add {
		if f.routes[key] {
			return api.Errorf(api.CodeAlreadyExists, "route: File exists")
		}
		f.routes[key] = true
		return nil
	}
	if !f.routes[key] {
		return api.Errorf(api.CodeNotFound, "route: not in table")
	}
	delete(f.routes, key)
	return nil
}

// RouteAdd implements Client.
func (f *Fake) RouteAdd(_ context.Context, r Route) error { return f.route(r, true) }

// RouteDelete implements Client.
func (f *Fake) RouteDelete(_ context.Context, r Route) error { return f.route(r, false) }

// IPv6Forwarding implements Client.
func (f *Fake) IPv6Forwarding(context.Context) (bool, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.Forwarding, nil
}
