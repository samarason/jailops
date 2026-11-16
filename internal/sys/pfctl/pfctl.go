// Package pfctl manages PF anchors and tables through pfctl(8). Rulesets go
// to pfctl on stdin, so no ruleset text ever appears on a command line.
package pfctl

import (
	"context"
	"fmt"
	"net/netip"
	"regexp"
	"sort"
	"strings"
	"time"

	"jailops.net/jailops/internal/sys/run"
	"jailops.net/jailops/sdk/api"
)

// MaxRulesetBytes bounds a ruleset accepted by Validate and Load.
const MaxRulesetBytes = 1 << 20

// Client manages anchors. The anchor name is the path below the root
// ruleset, e.g. "jailops/web".
type Client interface {
	// Validate runs a syntax check (pfctl -n) and returns the normalised
	// rules as pfctl prints them.
	Validate(ctx context.Context, anchor, ruleset string) (normalised string, err error)
	// Load validates, loads in one operation, reads the anchor back and
	// compares it with the validated rules.
	Load(ctx context.Context, anchor, ruleset string) error
	// Read returns the rules of the anchor: the filter rules and the translation options on them (match ... nat-to,
	// rdr-to).
	Read(ctx context.Context, anchor string) (string, error)
	// Flush removes the rules and the tables of the anchor.
	Flush(ctx context.Context, anchor string) error
	TableAdd(ctx context.Context, anchor, table string, addrs ...string) error
	TableDelete(ctx context.Context, anchor, table string, addrs ...string) error
	TableShow(ctx context.Context, anchor, table string) ([]string, error)
	// KillLabel removes the states that rules with this label created. The label is one JailOps put on a rule
	// (see ValidateLabel); a rule that was removed or changed no longer admits its flows, and a state would otherwise
	// keep them going until it expires.
	KillLabel(ctx context.Context, label string) error
}

// LabelPrefix starts every label JailOps puts on a pass rule.
const LabelPrefix = "jo-"

var labelRE = regexp.MustCompile(`^jo-[0-9a-f]{12}$`)

// ValidateLabel accepts only the labels JailOps generates.
func ValidateLabel(l string) error {
	if !labelRE.MatchString(l) {
		return api.Errorf(api.CodeInvalid, "invalid pf label %q", l)
	}
	return nil
}

// LabelsOf returns the labels that occur in pf rule text (as printed by pfctl -s rules or as rendered).
func LabelsOf(rules string) map[string]bool {
	out := map[string]bool{}
	for _, m := range labelInRulesRE.FindAllStringSubmatch(rules, -1) {
		out[m[1]] = true
	}
	return out
}

var labelInRulesRE = regexp.MustCompile(`label "(jo-[0-9a-f]{12})"`)

// KillLabel implements Client.
func (c *Command) KillLabel(ctx context.Context, label string) error {
	if err := ValidateLabel(label); err != nil {
		return err
	}
	if _, err := c.pf(ctx, "", "-k", "label", "-k", label); err != nil {
		return mapErr("kill states", err)
	}
	return nil
}

// ValidateAnchor accepts slash separated components of letters, digits, '_',
// '-' and '.', none empty, none starting with '-' or '.', at most 8 levels
// and 128 bytes. The empty (root) anchor is rejected: JailOps never loads
// into the root ruleset.
func ValidateAnchor(a string) error {
	bad := api.Errorf(api.CodeInvalid, "invalid pf anchor name %q", a)
	if a == "" || len(a) > 128 {
		return bad
	}
	parts := strings.Split(a, "/")
	if len(parts) > 8 {
		return bad
	}
	for _, p := range parts {
		if p == "" || p[0] == '-' || p[0] == '.' {
			return bad
		}
		for i := 0; i < len(p); i++ {
			c := p[i]
			if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '_' || c == '-' || c == '.') {
				return bad
			}
		}
	}
	return nil
}

// ValidateTable accepts PF table names: a letter then letters, digits and
// '_', at most 32 bytes.
func ValidateTable(t string) error {
	if t == "" || len(t) > 32 {
		return api.Errorf(api.CodeInvalid, "invalid pf table name %q", t)
	}
	for i := 0; i < len(t); i++ {
		c := t[i]
		letter := c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z'
		if !(letter || i > 0 && (c >= '0' && c <= '9' || c == '_')) {
			return api.Errorf(api.CodeInvalid, "invalid pf table name %q", t)
		}
	}
	return nil
}

// ValidateAddr accepts one IP address or CIDR prefix and returns its
// canonical text.
func ValidateAddr(s string) (string, error) {
	if p, err := netip.ParsePrefix(s); err == nil {
		return p.String(), nil
	}
	if a, err := netip.ParseAddr(s); err == nil && a.Zone() == "" {
		return a.String(), nil
	}
	return "", api.Errorf(api.CodeInvalid, "invalid table address %q", s)
}

func validateRuleset(r string) error {
	if len(r) > MaxRulesetBytes {
		return api.Errorf(api.CodeInvalid, "ruleset larger than %d bytes", MaxRulesetBytes)
	}
	if strings.ContainsRune(r, 0) {
		return api.Errorf(api.CodeInvalid, "ruleset contains a NUL byte")
	}
	return nil
}

// ruleKeywords begin the lines that pfctl -sr prints for rules.
var ruleKeywords = map[string]bool{
	"pass": true, "block": true, "match": true, "nat": true, "rdr": true, "binat": true,
	"anchor": true, "no": true, "nat-anchor": true, "rdr-anchor": true, "binat-anchor": true,
	"scrub": true, "antispoof": true,
}

// RuleLines extracts the rule lines from pfctl output, ignoring comments,
// blank lines, "set", "table" and diagnostic lines, and collapsing white
// space, so that the verbose dry run and the readback can be compared.
// The result is sorted: pfctl groups translation and filter rules
// differently in the two outputs and only the multiset is compared.
func RuleLines(out string) []string {
	var ls []string
	for _, l := range strings.Split(out, "\n") {
		f := strings.Fields(l)
		if len(f) == 0 || !ruleKeywords[f[0]] {
			continue
		}
		ls = append(ls, adaptiveTimeouts.ReplaceAllString(strings.Join(f, " "), ""))
	}
	sort.Strings(ls)
	return ls
}

// adaptiveTimeouts are the adaptive.start and adaptive.end values pf adds to a rule that has a state limit
// ("keep state (max 10000, adaptive.start 6000, adaptive.end 12000)"). The verbose dry run prints them on FreeBSD
// 15.1 and 15.2; the readback of the loaded rule prints them on 15.2 and leaves them out on 15.1. They are defaults
// derived from the limit, so they are left out of both sides of a comparison.
var adaptiveTimeouts = regexp.MustCompile(`, adaptive\.(start|end) [0-9]+`)

// firstDifference names the first rule that the two sorted lists do not share, for an error message.
func firstDifference(want, have []string) string {
	for i := 0; i < len(want) || i < len(have); i++ {
		switch {
		case i >= len(want):
			return fmt.Sprintf("read back but not expected: %q", have[i])
		case i >= len(have):
			return fmt.Sprintf("expected but not read back: %q", want[i])
		case want[i] != have[i]:
			return fmt.Sprintf("expected %q, read back %q", want[i], have[i])
		}
	}
	return ""
}

func mapErr(what string, err error) error {
	if err == nil {
		return nil
	}
	if ee, ok := run.IsExit(err); ok {
		msg := strings.TrimSpace(ee.Stderr)
		low := strings.ToLower(msg)
		switch {
		case strings.Contains(low, "syntax error"), strings.Contains(low, "unknown"), strings.Contains(low, "invalid"):
			return api.Errorf(api.CodeInvalid, "pfctl %s: %s", what, msg)
		case strings.Contains(low, "does not exist"), strings.Contains(low, "no such"), strings.Contains(low, "table not found"):
			return api.Errorf(api.CodeNotFound, "pfctl %s: %s", what, msg)
		}
		return api.Errorf(api.CodeInternal, "pfctl %s: %s", what, msg)
	}
	return api.Errorf(api.CodeInternal, "pfctl %s: %v", what, err)
}

// Command implements Client with pfctl.
type Command struct{ R run.Runner }

var _ Client = (*Command)(nil)

// NewCommand returns a Client that runs pfctl through r.
func NewCommand(r run.Runner) *Command { return &Command{R: r} }

func (c *Command) pf(ctx context.Context, stdin string, args ...string) (run.Result, error) {
	cmd := run.Cmd{Name: "pfctl", Args: args, Timeout: 30 * time.Second}
	if mutates(args) {
		unlock, err := lockPF(ctx)
		if err != nil {
			return run.Result{}, err
		}
		defer unlock()
	}
	if stdin != "" {
		cmd.Stdin = strings.NewReader(stdin)
	}
	return c.R.Run(ctx, cmd)
}

// Validate implements Client. UNVERIFIED: the verbose dry run (-n -v) is
// expected to print the normalised rules on stdout.
func (c *Command) Validate(ctx context.Context, anchor, ruleset string) (string, error) {
	if err := ValidateAnchor(anchor); err != nil {
		return "", err
	}
	if err := validateRuleset(ruleset); err != nil {
		return "", err
	}
	res, err := c.pf(ctx, ruleset, "-n", "-v", "-a", anchor, "-f", "-")
	if err != nil {
		return "", mapErr("validate", err)
	}
	return string(res.Stdout), nil
}

// Load implements Client: validate, load, read back, compare.
//
// UNVERIFIED: that pfctl -sn -sr output equals the -n -v output rule for rule
// after whitespace normalisation, and that the load is atomic, has not been
// run on FreeBSD (design section 16 item 3). A mismatch is reported as an
// error; the loaded rules are left in place so the operator can inspect them.
func (c *Command) Load(ctx context.Context, anchor, ruleset string) error {
	norm, err := c.Validate(ctx, anchor, ruleset)
	if err != nil {
		return err
	}
	if _, err := c.pf(ctx, ruleset, "-a", anchor, "-f", "-"); err != nil {
		return mapErr("load", err)
	}
	got, err := c.Read(ctx, anchor)
	if err != nil {
		return err
	}
	want, have := RuleLines(norm), RuleLines(got)
	if strings.Join(want, "\n") != strings.Join(have, "\n") {
		return api.Errorf(api.CodeInternal, "pf anchor %s: loaded rules differ from the validated ruleset (%d expected, %d read back): %s", anchor, len(want), len(have), firstDifference(want, have))
	}
	return nil
}

// Read implements Client.
func (c *Command) Read(ctx context.Context, anchor string) (string, error) {
	if err := ValidateAnchor(anchor); err != nil {
		return "", err
	}
	// The translation options stand on match and pass rules, so -sr lists everything the anchor holds.
	res, err := c.pf(ctx, "", "-a", anchor, "-sr")
	if err != nil {
		return "", mapErr("read", err)
	}
	return string(res.Stdout), nil
}

// Flush implements Client.
func (c *Command) Flush(ctx context.Context, anchor string) error {
	if err := ValidateAnchor(anchor); err != nil {
		return err
	}
	// Verified on FreeBSD 15.1: an anchor without rules and tables does not
	// exist any more, and flushing its tables then fails with "Operation not
	// supported by device". Tables go first, while the anchor still exists, and
	// that one error is the anchor being gone already.
	for _, what := range []string{"Tables", "rules"} {
		_, err := c.pf(ctx, "", "-a", anchor, "-F", what)
		if err != nil {
			if ee, ok := run.IsExit(err); ok && what == "Tables" && strings.Contains(strings.ToLower(ee.Stderr), "not supported by device") {
				continue
			}
			return mapErr("flush", err)
		}
	}
	return nil
}

func tableArgs(anchor, table, verb string, addrs []string) ([]string, error) {
	if err := ValidateAnchor(anchor); err != nil {
		return nil, err
	}
	if err := ValidateTable(table); err != nil {
		return nil, err
	}
	args := []string{"-a", anchor, "-t", table, "-T", verb}
	for _, a := range addrs {
		n, err := ValidateAddr(a)
		if err != nil {
			return nil, err
		}
		args = append(args, n)
	}
	return args, nil
}

// TableAdd implements Client.
func (c *Command) TableAdd(ctx context.Context, anchor, table string, addrs ...string) error {
	if len(addrs) == 0 {
		return api.Errorf(api.CodeInvalid, "no addresses given")
	}
	args, err := tableArgs(anchor, table, "add", addrs)
	if err != nil {
		return err
	}
	_, err = c.pf(ctx, "", args...)
	return mapErr("table add", err)
}

// TableDelete implements Client.
func (c *Command) TableDelete(ctx context.Context, anchor, table string, addrs ...string) error {
	if len(addrs) == 0 {
		return api.Errorf(api.CodeInvalid, "no addresses given")
	}
	args, err := tableArgs(anchor, table, "delete", addrs)
	if err != nil {
		return err
	}
	_, err = c.pf(ctx, "", args...)
	return mapErr("table delete", err)
}

// TableShow implements Client.
func (c *Command) TableShow(ctx context.Context, anchor, table string) ([]string, error) {
	args, err := tableArgs(anchor, table, "show", nil)
	if err != nil {
		return nil, err
	}
	res, err := c.pf(ctx, "", args...)
	if err != nil {
		return nil, mapErr("table show", err)
	}
	return ParseTable(string(res.Stdout)), nil
}

// ParseTable parses `pfctl -T show`: one address per line, indented, with
// an optional "*" prefix inside the line for negated entries kept verbatim.
func ParseTable(out string) []string {
	var r []string
	for _, l := range strings.Split(out, "\n") {
		if l = strings.TrimSpace(l); l != "" {
			r = append(r, l)
		}
	}
	return r
}
