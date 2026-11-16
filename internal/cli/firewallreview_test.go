package cli_test

import (
	"strings"
	"testing"

	"jailops.net/jailops/sdk/api"
)

const reviewDoc = `apiVersion: jailops/v1
kind: FirewallPolicy
metadata: {name: web}
spec:
  default_in: deny
  default_out: allow
  rules:
    - {name: site, action: allow, direction: in, proto: tcp, ports: ["443"], from: ["set:office"], comment: the site}
    - {name: anyone, action: allow, direction: in, proto: tcp}
    - {name: old, action: allow, direction: in, proto: tcp, ports: ["8080"], from: ["jail:ghost"], disabled: true, comment: the old port}
    - {name: ping, action: allow, direction: in, proto: icmp, comment: ping}
---
apiVersion: jailops/v1
kind: AddressSet
metadata: {name: office}
spec:
  comment: the office
  addresses: [{address: 192.0.2.0/24}, {address: 198.51.100.7, comment: the home line}]
---
apiVersion: jailops/v1
kind: AddressSet
metadata: {name: unused}
spec:
  addresses: [{address: 203.0.113.9, comment: nobody uses it}]
`

// --review adds warnings a reviewer would raise and never changes the exit status; without a server it says what it
// could not check.
func TestValidateReview(t *testing.T) {
	h := newHarness(t)
	h.seed()
	out, _, code := h.run(reviewDoc, "firewall", "validate", "-f", "-", "--review", "--offline")
	if code != 0 {
		t.Fatalf("a review changed the exit status: %d\n%s", code, out)
	}
	for _, w := range []string{
		"policy/web", "the policy has no comment", "rules[1] (anyone) has no comment", "rules[1] (anyone) is very broad",
		"rules[2] (old) is disabled", "address-set/office", "the member 192.0.2.0/24 has no comment",
		"address-set/unused", "the address set has no comment", "no rule and no address set refers to set:unused",
		"no server answered",
	} {
		if !strings.Contains(out, w) {
			t.Errorf("--review missed %q:\n%s", w, out)
		}
	}
	for _, not := range []string{"rules[0] (site) has no comment", "rules[3] (ping) is very broad", "the member 198.51.100.7 has no comment", "refers to set:office"} {
		if strings.Contains(out, not) {
			t.Errorf("--review said %q:\n%s", not, out)
		}
	}
	plain, _, code := h.run(reviewDoc, "firewall", "validate", "-f", "-", "--offline")
	if code != 0 || strings.Contains(plain, "review:") {
		t.Fatalf("without --review there are no review findings (exit %d):\n%s", code, plain)
	}
}

// With a server it also checks the jails and who uses a policy.
func TestValidateReviewWithAServer(t *testing.T) {
	h := newHarness(t)
	h.seed()
	h.srv.SeedImage(api.Image{Metadata: api.ObjectMeta{Name: "freebsd-151"},
		Spec: api.ImageSpec{OS: api.OSFreeBSD, Release: "15.1-RELEASE", Arch: "amd64", Source: api.ImageSource{Type: "pkgbase"}, Aliases: []string{"stable"}}})
	h.srv.SeedGeneration("freebsd-151")
	if o, e, code := h.run("", "app", "install", "nginx", "web", "--image", "freebsd-151@stable"); code != 0 {
		t.Fatalf("%s %s", o, e)
	}
	out, _, code := h.run(reviewDoc, "firewall", "validate", "-f", "-", "--review")
	if code != 0 {
		t.Fatalf("exit %d\n%s", code, out)
	}
	for _, w := range []string{"names jail:ghost, which does not exist", "no jail and no project uses this policy"} {
		if !strings.Contains(out, w) {
			t.Errorf("--review with a server missed %q:\n%s", w, out)
		}
	}
	if strings.Contains(out, "no server answered") {
		t.Errorf("a server answered:\n%s", out)
	}
}
