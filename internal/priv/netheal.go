package priv

import (
	"context"
	"fmt"
	"sort"
	"time"

	"jailops.net/jailops/internal/ipam"
	"jailops.net/jailops/internal/render"
	"jailops.net/jailops/internal/sys/run"
)

// HealNetRes says which interfaces net.heal destroyed and which it left, with the reason.
type HealNetRes struct {
	Destroyed []string `json:"destroyed,omitempty"`
	Skipped   []string `json:"skipped,omitempty"`
}

// HealNetwork destroys what the earlier network layout made and this one does not use: a bridge, and the gateway pair of
// a network (an epair whose name is not the one JailOps derives for the link of a jail). Only interfaces that carry the
// JailOps marker in their description are considered, and none that a jail which runs uses: a bridge that still has a
// link of a running jail as a member stays (that jail was started before the upgrade and has to be restarted first).
// The uplink and the links of jails never qualify.
func (l *Local) HealNetwork(ctx context.Context) (HealNetRes, error) {
	var res HealNetRes
	ifs, err := l.d.Net.List(ctx)
	if err != nil {
		return res, err
	}
	live := map[string]bool{} // the host ends of the links of the jails that run
	unreadable := false
	list, err := l.d.Jails.List(ctx)
	if err != nil {
		return res, err
	}
	for _, j := range list {
		jn, err := ParseJailName(j.Name)
		if err != nil {
			continue
		}
		atts, err := l.planJail(ctx, jn)
		if err != nil {
			unreadable = true // the links of a jail that runs are not known: no bridge is taken away below
			continue
		}
		for _, a := range atts {
			live[a.host] = true
		}
	}
	gone := map[string]bool{}
	for _, i := range ifs {
		if gone[i.Name] || !render.IsJailOpsDesc(i.Description) {
			continue
		}
		var bridge, epair bool
		for _, g := range i.Groups {
			bridge = bridge || g == "bridge"
			epair = epair || g == "epair"
		}
		switch {
		case bridge:
			if unreadable {
				res.Skipped = append(res.Skipped, fmt.Sprintf("%s: a jail that runs could not be read, so its links are not known", i.Name))
				continue
			}
			held := ""
			for _, m := range i.Members {
				if live[m.Name] {
					held = m.Name
					break
				}
			}
			if held != "" {
				res.Skipped = append(res.Skipped, fmt.Sprintf("%s: the link %s of a jail that runs is still a member", i.Name, held))
				continue
			}
		case epair && !ipam.IsEpairName(i.Name):
			// the gateway pair of a network; destroying one end removes the other
		default:
			continue
		}
		if _, err := l.d.Runner.Run(ctx, run.Cmd{Name: "ifconfig", Args: []string{i.Name, "destroy"}, Timeout: 20 * time.Second}); err != nil {
			res.Skipped = append(res.Skipped, i.Name+": "+err.Error())
			continue
		}
		res.Destroyed = append(res.Destroyed, i.Name)
		gone[i.Name] = true
		if epair && len(i.Name) > 1 { // the other end of the pair went with it
			twin := i.Name[:len(i.Name)-1]
			if i.Name[len(i.Name)-1] == 'a' {
				gone[twin+"b"] = true
			} else {
				gone[twin+"a"] = true
			}
		}
	}
	sort.Strings(res.Destroyed)
	return res, nil
}
