package cli

import (
	"encoding/json"
	"fmt"
	"reflect"
	"strconv"
	"strings"

	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
)

// "set NAME --flag ..." changes single attributes of an object from the flags of its "create", without an editor.
// Only the flags that were given change anything. The object is read, the flags are turned into an object by the
// builder of "create" (once with the flags given and once with none), and the fields in which the two differ are laid
// over the stored specification: a flag left out leaves its field alone, a list flag replaces the whole list, an
// empty value clears it. A flag given with its own default value is found by building once more with another value
// of that flag, which tells which fields it controls; the fields go back to their defaults.

// addSet adds "set NAME" to the group of a kind that is created from flags.
func addSet[T any](a *app, parent *cobra.Command, d *kindDesc[T], flagBuild func(*cobra.Command) func(string) (T, error)) {
	cmd := &cobra.Command{
		Use:   "set NAME",
		Short: "Change attributes of " + article(d.noun) + " " + d.noun,
		Long: `Change attributes of ` + article(d.noun) + ` ` + d.noun + ` with the flags of create: only the flags you give change
anything. A list flag replaces the whole list, and an empty value clears it; --env and --label add to the
stored ones (remove one with 'jailops config unset'). The
update carries the ETag of the version that was read, so a change made in the
meantime is refused, not overwritten. --dry-run prints the new document and sends
nothing. To change the whole document in an editor use edit.`,
		Example:           "@SET@",
		Args:              cobra.ExactArgs(1),
		ValidArgsFunction: completeKind(a, d),
	}
	build := flagBuild(cmd)
	cmd.RunE = func(cmd *cobra.Command, args []string) error {
		name := args[0]
		if !anyFlagGiven(cmd) {
			return usagef("nothing to change: give at least one flag (jailops %s set --help)", strings.TrimPrefix(cmd.Parent().CommandPath(), "jailops "))
		}
		c, err := a.connect(cmd.Context())
		if err != nil {
			return err
		}
		obj, etag, err := d.get(cmd.Context(), c, name)
		if err != nil {
			return err
		}
		a.partial = true
		defer func() { a.partial = false }()
		built, err := build(name)
		if err != nil {
			return err
		}
		base, err := baselineOf(flagBuild, name)
		if err != nil {
			return err
		}
		merged, notes, err := mergeSet(d, cmd, flagBuild, name, obj, built, base)
		if err != nil {
			return err
		}
		for _, n := range notes {
			fprintln(a.env.Stderr, n)
		}
		if sameDocument(d, obj, merged) {
			a.say("%s/%s unchanged\n", d.noun, name)
			return nil
		}
		if ok, err := a.dry("update "+d.noun+" "+name, document(d.kind, *d.meta(&merged), d.specOf(&merged))); ok || err != nil {
			return err
		}
		out, err := d.update(cmd.Context(), c, name, merged, etag)
		if err != nil {
			return err
		}
		if err := a.finishOp(cmd.Context(), nil, d.noun, name, "updated", out); err != nil {
			return err
		}
		if d.updated != nil {
			d.updated(a, out)
		}
		return nil
	}
	parent.AddCommand(cmd)
}

// anyFlagGiven reports whether the command line named a flag of its own (the global flags are not its attributes).
func anyFlagGiven(cmd *cobra.Command) bool {
	n := 0
	cmd.LocalNonPersistentFlags().VisitAll(func(f *pflag.Flag) {
		if f.Changed {
			n++
		}
	})
	return n > 0
}

// baselineOf builds the object of a create with no flag given: the defaults.
func baselineOf[T any](flagBuild func(*cobra.Command) func(string) (T, error), name string) (T, error) {
	return flagBuild(&cobra.Command{Use: "x"})(name)
}

// mergeSet lays the fields that the given flags set over a copy of obj.
func mergeSet[T any](d *kindDesc[T], cmd *cobra.Command, flagBuild func(*cobra.Command) func(string) (T, error), name string, obj, built, base T) (T, []string, error) {
	var zero T
	om, err := specMap(d.specOf(&obj))
	if err != nil {
		return zero, nil, err
	}
	bm, err := specMap(d.specOf(&built))
	if err != nil {
		return zero, nil, err
	}
	zm, err := specMap(d.specOf(&base))
	if err != nil {
		return zero, nil, err
	}
	overlay(om, bm, zm)
	var notes []string
	// a flag given with its own default value changes nothing in the diff above: find the fields it controls
	var reset []string
	cmd.LocalNonPersistentFlags().VisitAll(func(f *pflag.Flag) {
		if f.Changed && f.Value.String() == f.DefValue {
			reset = append(reset, f.Name)
		}
	})
	for _, fl := range reset {
		probe, ok := probeValue(cmd.Flags().Lookup(fl))
		if !ok {
			notes = append(notes, fmt.Sprintf("note: --%s has its default value, which set cannot tell from leaving it out; use edit to set it", fl))
			continue
		}
		alt, err := probeBuild(flagBuild, name, fl, probe)
		if err != nil {
			notes = append(notes, fmt.Sprintf("note: --%s has its default value, which set cannot tell from leaving it out; use edit to set it", fl))
			continue
		}
		am, err := specMap(d.specOf(&alt))
		if err != nil {
			return zero, nil, err
		}
		restore(om, am, zm)
	}
	next := obj
	var fresh T
	*d.meta(&fresh) = *d.meta(&obj)
	b, err := json.Marshal(om)
	if err != nil {
		return zero, nil, err
	}
	if err := json.Unmarshal(b, d.specOf(&fresh)); err != nil {
		return zero, nil, fmt.Errorf("the changed specification is not valid: %w", err)
	}
	d.setSpec(&next, fresh)
	// labels given on the command line are added to the stored ones
	if bl, zl := d.meta(&built).Labels, d.meta(&base).Labels; !reflect.DeepEqual(bl, zl) {
		labels := map[string]string{}
		for k, v := range d.meta(&obj).Labels {
			labels[k] = v
		}
		for k, v := range bl {
			labels[k] = v
		}
		d.meta(&next).Labels = labels
	}
	return next, notes, nil
}

// specMap is the JSON form of a specification as a map.
func specMap(spec any) (map[string]any, error) {
	b, err := json.Marshal(spec)
	if err != nil {
		return nil, err
	}
	var m map[string]any
	if err := json.Unmarshal(b, &m); err != nil {
		return nil, err
	}
	if m == nil {
		m = map[string]any{}
	}
	return m, nil
}

// overlay sets in dst every field in which built differs from base, going into objects that both have, and removes
// the fields that base has and built has not (a value cleared).
func overlay(dst, built, base map[string]any) {
	for k, bv := range built {
		if same(bv, base, k) {
			continue
		}
		bm, ok1 := bv.(map[string]any)
		dm, ok2 := dst[k].(map[string]any)
		if ok1 && ok2 {
			zm, _ := base[k].(map[string]any)
			overlay(dm, bm, zm)
			continue
		}
		dst[k] = bv
	}
	for k := range base {
		if _, ok := built[k]; !ok {
			delete(dst, k)
		}
	}
}

// restore puts into dst the default of every field in which alt differs from base: the fields a flag controls.
func restore(dst, alt, base map[string]any) {
	for k, av := range alt {
		if same(av, base, k) {
			continue
		}
		am, ok1 := av.(map[string]any)
		dm, ok2 := dst[k].(map[string]any)
		if ok1 && ok2 {
			zm, _ := base[k].(map[string]any)
			restore(dm, am, zm)
			continue
		}
		if bv, ok := base[k]; ok {
			dst[k] = bv
		} else {
			delete(dst, k)
		}
	}
	for k, bv := range base {
		if _, ok := alt[k]; !ok {
			dst[k] = bv
		}
	}
}

// probeValue is another value for a flag, to find out which fields it controls; ok is false for a kind of flag
// where none can be made up.
func probeValue(f *pflag.Flag) (string, bool) {
	if f == nil {
		return "", false
	}
	switch f.Value.Type() {
	case "stringArray", "stringSlice":
		return "probe", true
	case "bool":
		if f.DefValue == "true" {
			return "false", true
		}
		return "true", true
	case "int", "int64", "uint", "uint64", "int32":
		n, err := strconv.ParseInt(f.DefValue, 10, 64)
		if err != nil {
			return "", false
		}
		return strconv.FormatInt(n+1, 10), true
	}
	return "", false
}

// probeBuild builds the object of a create with only flag fl, set to probe.
func probeBuild[T any](flagBuild func(*cobra.Command) func(string) (T, error), name, fl, probe string) (T, error) {
	var zero T
	c := &cobra.Command{Use: "x"}
	build := flagBuild(c)
	if err := c.Flags().Set(fl, probe); err != nil {
		return zero, err
	}
	return build(name)
}

// same reports whether v is what base has under k; a field that base does not have is the zero value of its type.
func same(v any, base map[string]any, k string) bool {
	bv, ok := base[k]
	if !ok {
		return isZero(v)
	}
	return reflect.DeepEqual(v, bv)
}

func isZero(v any) bool {
	switch x := v.(type) {
	case nil:
		return true
	case string:
		return x == ""
	case float64:
		return x == 0
	case bool:
		return !x
	case []any:
		return len(x) == 0
	case map[string]any:
		for _, e := range x {
			if !isZero(e) {
				return false
			}
		}
		return true
	}
	return false
}

// setExamples are the examples of "set", by group: real flags of the group's create.
var setExamples = map[string]string{
	"backup policy":        "backup policy set nightly --keep-daily 14",
	"backup target":        "backup target set offsite --url https://backup.example.com:39111",
	"cert":                 "cert set laptop --role operator",
	"firewall address-set": "firewall address-set set office --comment \"the office\"",
	"firewall policy":      "firewall policy set web --comment \"the public web server\"",
	"host":                 "host set freebsd01 --url https://192.0.2.10:39110",
	"image":                "image set freebsd-15-1 --keep-days 30",
	"jail":                 "jail set web --memory 4G --autostart",
	"network":              "network set lan --mtu 1450",
	"profile":              "profile set small --set limits.memory=1G",
	"storage":              "storage set default --compression lz4",
	"volume":               "volume set maildir --size 50G",
	"wireguard":            "wireguard set wg0 --listen-port 51821",
}

// setExample is the EXAMPLES section of the "set" of a group.
func setExample(group string) string {
	e, ok := setExamples[group]
	if !ok {
		e = group + " set NAME --help"
	}
	return "jailops " + e + "\njailops " + e + " --dry-run"
}

// dropEmpty removes the empty entries of a list flag: an empty value clears the list (--tag "") and is no entry of it.
func dropEmpty(l []string) []string {
	var out []string
	for _, v := range l {
		if v != "" {
			out = append(out, v)
		}
	}
	return out
}
