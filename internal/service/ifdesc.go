package service

import (
	"context"
	"sort"
	"strings"
	"time"

	"jailops.net/jailops/internal/reconcile"
	"jailops.net/jailops/internal/render"
	"jailops.net/jailops/internal/sys/ifconfig"
	"jailops.net/jailops/internal/sys/run"
	"jailops.net/jailops/sdk/api"
)

// doctorDescriptions is the check net.descriptions: every interface JailOps owns carries its description (both ends of
// every running jail's epairs, every WireGuard interface).
// What is missing or different is listed; the reconcile loop sets it on its next pass. An interface with a name
// JailOps would use but a description it does not write is foreign and left to the network checks.
func (s *Service) doctorDescriptions(ctx context.Context, c *checkSet) {
	if s.d.Net == nil {
		c.add("net.descriptions", api.DoctorUnknown, "interfaces cannot be read here", "")
		return
	}
	des, err := s.Desired(ctx)
	if err != nil {
		c.add("net.descriptions", api.DoctorUnknown, err.Error(), "")
		return
	}
	list, err := s.d.Net.List(ctx)
	if err != nil {
		c.add("net.descriptions", api.DoctorUnknown, err.Error(), "")
		return
	}
	ifs := map[string]ifconfig.Iface{}
	for _, i := range list {
		ifs[i.Name] = i
	}
	var bad []string
	quote := func(d string) string {
		if d == "" {
			return "none"
		}
		return "\"" + d + "\""
	}
	// a jail's epairs are named after the jail: one with no description or another JailOps text is the jail's
	check := func(name, want string) {
		if i, ok := ifs[name]; ok && want != "" && i.Description != want && (i.Description == "" || render.IsJailOpsDesc(i.Description)) {
			bad = append(bad, name+" ("+quote(i.Description)+")")
		}
	}
	running := map[string]bool{}
	if s.d.Jails != nil {
		if obs, err := reconcile.Observe(ctx, nil, s.d.Jails); err == nil {
			for k := range obs.Running {
				running[k] = true
			}
		}
	}
	for _, j := range des.Jails {
		if !running[j.Name] {
			continue
		}
		for _, steps := range j.Attach {
			for _, st := range steps {
				if st.Op == render.OpSetDescription {
					check(st.Iface, st.Arg)
				}
			}
		}
		for _, st := range j.JailSide {
			if got, ok := s.jailIfaceDesc(ctx, j.Name, st.Iface); ok && got != st.Arg {
				bad = append(bad, j.Name+":"+st.Iface+" ("+quote(got)+")")
			}
		}
	}
	// a tunnel's interface is ours when the helper says it created it
	bad = append(bad, s.wireguardDescChecks(ctx, quote)...)
	sort.Strings(bad)
	if len(bad) > 0 {
		c.add("net.descriptions", api.DoctorWarn, "interfaces of JailOps without their description: "+strings.Join(bad, ", "),
			"the reconcile loop sets them on its next pass; run `jailops doctor` again afterwards")
		return
	}
	c.add("net.descriptions", api.DoctorOK, "every interface of JailOps carries its description", "")
}

// jailIfaceDesc reads the description of an interface inside a running jail's vnet (ifconfig -j).
func (s *Service) jailIfaceDesc(ctx context.Context, jail, iface string) (string, bool) {
	if s.d.Run == nil {
		return "", false
	}
	res, err := s.d.Run.Run(ctx, run.Cmd{Name: "ifconfig", Args: []string{"-j", jail, iface}, Timeout: 10 * time.Second})
	if err != nil {
		return "", false
	}
	l := ifconfig.ParseIfconfig(string(res.Stdout))
	if len(l) != 1 {
		return "", false
	}
	return l[0].Description, true
}
