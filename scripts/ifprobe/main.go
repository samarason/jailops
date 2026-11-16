//go:build freebsd

// ifprobe asks the running helper, over its socket, for the interface operations a compromised daemon could ask for,
// and checks that the helper refuses every one on an interface JailOps did not create (docs/security-model.md,
// "Interfaces"), and accepts what JailOps needs. It is a test tool only, for scripts/ci-freebsd-e2e.sh: built for
// FreeBSD and run as root on a disposable machine, after the end-to-end flow has started the managed jail JAIL.
// Nothing in JailOps itself uses it.
//
//	ifprobe -uplink vtnet0 -foreign mybr -bare epair7a -jail edge_edgeweb
//
// FOREIGN is a bridge made by hand (ifconfig bridge create; ifconfig bridgeN name mybr), BARE an epair made by hand
// without a description (ifconfig epair create): the helper refuses both. Every check prints one line; the exit
// status is 1 when one failed.
package main

import (
	"context"
	"flag"
	"fmt"
	"net/netip"
	"os"
	"strings"

	"jailops.net/jailops/internal/priv"
	"jailops.net/jailops/internal/sys/ifconfig"
	"jailops.net/jailops/internal/sys/run"
	"jailops.net/jailops/sdk/api"
)

var failed int

func check(name string, ok bool, detail any) {
	if ok {
		fmt.Printf("ok   %s\n", name)
		return
	}
	failed++
	fmt.Printf("FAIL %s: %v\n", name, detail)
}

// refused: the helper said forbidden or invalid, never yes and never something else.
func refused(name string, err error) {
	check(name+" is refused", err != nil && (api.IsCode(err, api.CodeForbidden) || api.IsCode(err, api.CodeInvalid)), err)
}

func main() {
	sock := flag.String("socket", priv.DefaultSocket, "the helper's socket")
	uplink := flag.String("uplink", "", "the host's uplink")
	foreign := flag.String("foreign", "", "a bridge made by hand")
	bare := flag.String("bare", "", "an epair made by hand, without a description")
	jail := flag.String("jail", "", "a running managed jail (its internal name)")
	flag.Parse()
	if *uplink == "" || *foreign == "" || *bare == "" || *jail == "" {
		flag.Usage()
		os.Exit(2)
	}
	c, err := priv.Dial(*sock)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}
	defer c.Close()
	ctx := context.Background()
	n := c.Net()
	desc := func(name string) string {
		list, err := n.List(ctx)
		if err != nil {
			return "error: " + err.Error()
		}
		for _, i := range list {
			if i.Name == name {
				return i.Description
			}
		}
		return "(missing)"
	}
	before := map[string]string{}
	for _, name := range []string{*uplink, "lo0", *foreign, *bare} {
		before[name] = desc(name)
	}

	// 1. nothing that is not JailOps's is changed; the requests are harmless if they were carried out by mistake
	for _, name := range []string{*uplink, "lo0", *foreign, *bare} {
		refused("destroy (epair) "+name, n.EpairDestroy(ctx, name))
		refused("link up "+name, n.SetLink(ctx, name, true))
		refused("address on "+name, n.AddrAdd(ctx, name, netip.MustParsePrefix("192.0.2.77/32")))
		refused("the marker written on "+name, n.SetDescription(ctx, name, ifconfig.Marker))
		refused("a JailOps text written on "+name, n.SetDescription(ctx, name, "jailops jail=p/x net=lan (host side)"))
		refused("route through "+name, n.RouteAdd(ctx, ifconfig.Route{Dest: "2001:db8::77/128", Interface: name}))
		refused("mtu of "+name, c.SetMTU(ctx, name, 1400))
		refused("move "+name+" into "+*jail, n.MoveToJail(ctx, name, *jail))
	}
	for name, was := range before {
		check("the description of "+name+" is unchanged", desc(name) == was, desc(name))
	}

	// 2. no reject route for a prefix that is not the subnet of a network of JailOps; a driver's name is never created
	for _, p := range []string{"0.0.0.0/0", "10.0.0.0/8", "::/0"} {
		refused("a reject route for "+p, n.RouteAdd(ctx, ifconfig.Route{Dest: p, Reject: true}))
	}
	if _, _, err := n.EpairCreate(ctx, "epair9"); !api.IsCode(err, api.CodeInvalid) {
		check("epair epair9a/epair9b is refused", false, err)
	} else {
		check("epair epair9a/epair9b is refused", true, nil)
	}

	// 3. no command line makes or renames a host interface
	for _, argv := range [][]string{{"bridge", "create"}, {"epair", "create"}, {"bridge0", "name", "jo5"}, {*uplink, "name", "jo5"}, {*foreign, "destroy"}} {
		_, err := c.Runner().Run(ctx, run.Cmd{Name: "ifconfig", Args: argv})
		refused("ifconfig "+strings.Join(argv, " ")+" through the runner", err)
	}
	_, err = c.Runner().Run(ctx, run.Cmd{Name: "ifconfig", Args: []string{"-j", *jail, "lo0", "down"}})
	refused("ifconfig -j "+*jail+" lo0 down", err)

	// 4. an epair without a description is not JailOps's, whatever its name
	check(*bare+" has no description", desc(*bare) == "", desc(*bare))
	refused(*bare+" is refused", n.SetLink(ctx, *bare, true))
	check(*bare+" is still undescribed", desc(*bare) == "", desc(*bare))

	// 5. what JailOps makes carries the marker from its creation, in the jail's vnet too
	a, b, err := n.EpairCreate(ctx, "joprobe")
	check("epair joprobea/joprobeb is created", err == nil && a == "joprobea" && b == "joprobeb", err)
	check("joprobea carries the marker", desc("joprobea") == ifconfig.Marker, desc("joprobea"))
	check("joprobeb moves into "+*jail, n.MoveToJail(ctx, b, *jail) == nil, nil)
	out, err := c.Runner().Run(ctx, run.Cmd{Name: "ifconfig", Args: []string{"-j", *jail, b}})
	check("joprobeb keeps the marker in the jail's vnet", err == nil && strings.Contains(string(out.Stdout), "description: "+ifconfig.Marker), string(out.Stdout))
	_, err = c.Runner().Run(ctx, run.Cmd{Name: "ifconfig", Args: []string{"-j", *jail, b, "up"}})
	check("ifconfig -j "+*jail+" joprobeb up", err == nil, err)
	check("joprobeb comes back", n.MoveFromJail(ctx, b, *jail) == nil, nil)
	refused("a description that drops the marker", n.SetDescription(ctx, a, "my link"))
	check("the pair is destroyed", n.EpairDestroy(ctx, a) == nil, nil)

	if failed > 0 {
		fmt.Printf("%d checks failed\n", failed)
		os.Exit(1)
	}
	fmt.Println("all checks passed")
}
