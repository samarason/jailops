package render

import (
	"fmt"
	"strings"
	"testing"
)

// A number never changes while its device exists, whatever is added or removed around it; new directions get the lowest
// free numbers, and no two share a pipe.
func TestAllocatePipesKeepsNumbers(t *testing.T) {
	var keys []PipeKey
	for i := 0; i < 5000; i++ {
		keys = append(keys, PipeKey{Jail: fmt.Sprintf("0b0e7f3e-5c4b-4f6e-9d3e-%012d", i), Device: i % 3, Ingress: i%2 == 0})
	}
	first, err := AllocatePipes(nil, keys)
	if err != nil {
		t.Fatal(err)
	}
	seen := map[int]PipeKey{}
	for _, k := range keys {
		n := first[k]
		if !IsManagedPipe(n) {
			t.Fatalf("%v: pipe %d is outside the range", k, n)
		}
		if o, dup := seen[n]; dup {
			t.Fatalf("pipe %d of %v is also the pipe of %v", n, k, o)
		}
		seen[n] = k
	}
	// every other device goes, a new one comes: the rest keep their numbers
	var rest []PipeKey
	for i, k := range keys {
		if i%2 == 0 {
			rest = append(rest, k)
		}
	}
	added := PipeKey{Jail: "00000000-0000-0000-0000-00000000ffff", Device: 0}
	second, err := AllocatePipes(first, append([]PipeKey{added}, rest...))
	if err != nil {
		t.Fatal(err)
	}
	for _, k := range rest {
		if second[k] != first[k] {
			t.Fatalf("%v: %d became %d", k, first[k], second[k])
		}
	}
	for _, k := range rest {
		if second[k] == second[added] {
			t.Fatalf("the new key got %d, which %v keeps", second[added], k)
		}
	}
	if !IsManagedPipe(second[added]) {
		t.Fatalf("the new key got %d, outside the range", second[added])
	}
	// the order the keys come in does not matter for new numbers
	rev := append([]PipeKey(nil), keys...)
	for i, j := 0, len(rev)-1; i < j; i, j = i+1, j-1 {
		rev[i], rev[j] = rev[j], rev[i]
	}
	again, err := AllocatePipes(nil, rev)
	if err != nil {
		t.Fatal(err)
	}
	for _, k := range keys {
		if again[k] != first[k] {
			t.Fatalf("%v: %d then %d", k, first[k], again[k])
		}
	}
	// the two directions of one device have two pipes
	if first[PipeKey{Jail: keys[0].Jail, Device: 0, Ingress: true}] == first[PipeKey{Jail: keys[0].Jail, Device: 0}] {
		t.Fatal("the directions share a pipe")
	}
}

// A kept number that is outside the range, or given twice, is not kept.
func TestAllocatePipesDropsBadKeptNumbers(t *testing.T) {
	a, b, c := PipeKey{Jail: "a"}, PipeKey{Jail: "b"}, PipeKey{Jail: "c"}
	got, err := AllocatePipes(map[PipeKey]int{a: PipeBase + 5, b: PipeBase + 5, c: 7}, []PipeKey{a, b, c})
	if err != nil {
		t.Fatal(err)
	}
	if got[a] != PipeBase+5 || got[b] == got[a] || got[c] == 7 || !IsManagedPipe(got[b]) || !IsManagedPipe(got[c]) || got[b] == got[c] {
		t.Fatalf("%v", got)
	}
}

func TestAllocatePipesRefuseMoreDevicesThanPipes(t *testing.T) {
	var keys []PipeKey
	for i := 0; i <= PipeSpan; i++ {
		keys = append(keys, PipeKey{Jail: fmt.Sprintf("j%d", i)})
	}
	if _, err := AllocatePipes(nil, keys); err == nil {
		t.Fatal("more devices than pipes accepted")
	}
}

func TestPipeRate(t *testing.T) {
	if PipeRate(10000000) != "10000000bit/s" {
		t.Fatal(PipeRate(10000000))
	}
}

// A device with a limit sends what the jail sends into its egress pipe and what the jail receives into its ingress
// pipe, with match rules before the filter rules, both on the host end of the jail's epair.
func TestShapingMatchRules(t *testing.T) {
	in := pfBase()
	in.Shaping = []Shape{{Iface: "jo0123456789a0a", Egress: 40000, Ingress: 40001}}
	s, err := PFAnchor(in)
	if err != nil {
		t.Fatal(err)
	}
	golden(t, "pf_anchor_shaping", s)
	out := "match in on jo0123456789a0a all dnpipe (40000, 40001)"
	into := "match out on jo0123456789a0a all dnpipe (40001, 40000)"
	if !strings.Contains(s, out) || !strings.Contains(s, into) {
		t.Fatalf("the match rules are missing:\n%s", s)
	}
	if strings.Index(s, out) > strings.Index(s, "pass ") || strings.Index(s, into) > strings.Index(s, "pass ") {
		t.Fatalf("a match rule comes after the first pass rule:\n%s", s)
	}
	// one direction only
	egressOnly := pfBase()
	egressOnly.Shaping = []Shape{{Iface: "jo0123456789a0a", Egress: 40000}}
	one, _ := PFAnchor(egressOnly)
	// both rules carry the pipe, so that a connection the host opens is shaped on the jail's way out as well
	if !strings.Contains(one, "match in on jo0123456789a0a all dnpipe (40000, 0)") || !strings.Contains(one, "match out on jo0123456789a0a all dnpipe (0, 40000)") {
		t.Fatalf("an egress limit alone renders the pipe for the jail's sending in both directions of a state:\n%s", one)
	}
	// no shaping, no pipes
	plain, _ := PFAnchor(pfBase())
	if strings.Contains(plain, "dnpipe") {
		t.Fatalf("an anchor without a limit has dnpipe:\n%s", plain)
	}
	// the match rules are not filter rules: the rule list the simulator walks is unchanged
	noShaping := in
	noShaping.Shaping = nil
	b1, _ := BuildAnchor(in)
	b2, _ := BuildAnchor(noShaping)
	if len(b1.Rules) != len(b2.Rules) {
		t.Fatalf("%d rules with a limit, %d without", len(b1.Rules), len(b2.Rules))
	}
}

// The packet that comes out of a port forward's translation is passed by a rule of its own, which carries a label,
// so that the state of the connection can be ended by the label when the forward goes away.
func TestForwardHasALabelledPassRule(t *testing.T) {
	s, err := PFAnchor(pfBase())
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		"match in on em0 inet proto tcp from any to (em0) port 8080 rdr-to 10.20.0.10 port 80",
		"pass in quick on em0 inet proto tcp from any to 10.20.0.10 port 80 label \"jo-",
		"pass in quick on em0 inet6 proto tcp from any to 2001:db8:1::100 port 80 label \"jo-",
	} {
		if !strings.Contains(s, want) {
			t.Errorf("missing %q:\n%s", want, s)
		}
	}
}
