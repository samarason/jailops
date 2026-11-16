package service

import (
	"context"
	"fmt"
	"slices"
	"strings"

	"jailops.net/jailops/internal/ipam"
	"jailops.net/jailops/internal/render"
	"jailops.net/jailops/sdk/api"
)

// doctorOldNetwork finds what an earlier version made for a network and this version does not use: a bridge named after
// the network and the gateway pair beside it (its host end carried the network's gateway address). A network is routed
// now: every jail has a link of its own and nothing belongs to the network itself, so these interfaces are leftovers.
// The jails that were started before the upgrade are still members of the bridge until they are restarted.
func (s *Service) doctorOldNetwork(ctx context.Context, c *checkSet) {
	if s.d.Net == nil {
		return
	}
	ifs, err := s.d.Net.List(ctx)
	if err != nil {
		c.add("network.leftovers", api.DoctorUnknown, err.Error(), "")
		return
	}
	var left, cmds, gateways []string
	bridges := 0
	linked := map[string]bool{} // links of jails that are still members of an old bridge
	for _, i := range ifs {
		if !render.IsJailOpsDesc(i.Description) {
			continue
		}
		var bridge, epair bool
		for _, g := range i.Groups {
			bridge = bridge || g == "bridge"
			epair = epair || g == "epair"
		}
		switch {
		case bridge:
			bridges++
			left = append(left, i.Name+" (bridge)")
			cmds = append(cmds, "ifconfig "+i.Name+" destroy")
			for _, m := range i.Members {
				if ipam.IsEpairName(m.Name) {
					linked[m.Name] = true
				}
			}
		case epair && !ipam.IsEpairName(i.Name):
			// a jail's link has a name JailOps derives from the jail; the gateway pair of a network had another one
			left = append(left, i.Name+" (gateway)")
			if strings.HasSuffix(i.Name, "ga") {
				cmds = append(cmds, "ifconfig "+i.Name+" destroy") // destroying one end removes the pair
			}
			for _, p := range append(slices.Clone(i.Inet), i.Inet6...) {
				gateways = append(gateways, p.String()+" on "+i.Name)
			}
		}
	}
	if len(left) == 0 {
		c.add("network.leftovers", api.DoctorOK, "no interfaces of an earlier network layout", "")
		return
	}
	var msg, hint []string
	if len(left) > 0 {
		msg = append(msg, "interfaces of the earlier layout, where every network had a bridge and a gateway pair: "+strings.Join(left, ", "))
		if len(gateways) > 0 {
			msg = append(msg, "the gateway address of a network that is routed now is still on "+strings.Join(gateways, ", ")+
				", so the link of a new jail cannot get it until it is taken away")
		}
		if len(linked) > 0 {
			msg = append(msg, fmt.Sprintf("%d jail links are still members of the bridge: restart those jails (jailops restart JAIL) so they get the routed link", len(linked)))
		}
		hint = append(hint, "after the jails were restarted: "+strings.Join(cmds, "; "))
	}
	if len(left) > 0 && bridges > 0 {
		hint = append(hint, "then kldunload if_bridge and remove if_bridge_load from /boot/loader.conf (the routed network does not use it)")
	}
	c.add("network.leftovers", api.DoctorWarn, strings.Join(msg, "; "), strings.Join(hint, "; "))
}
