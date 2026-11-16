// Package render turns typed inputs into configuration text: jail.conf,
// fstab, in-jail rc.conf and resolv.conf, Alpine interfaces files, PF
// anchors, reconcile plans and canonical JSON. Every function is pure.
//
// Injection safety rests on one rule: a value reaches output only after it
// matched a strict allow-list (names, paths, interface names) or was produced
// by a typed formatter (netip, strconv). Values are rejected, never
// "escaped into" a dangerous context, and no value may contain whitespace,
// quotes, backslashes, '$', ';', braces or control characters unless the
// field is documented otherwise.
package render

import (
	"fmt"
	"regexp"
	"strings"
)

var safeValueRE = regexp.MustCompile(`^[A-Za-z0-9._+@:=,/%-]+$`)

// safeValue returns s unchanged when it is non-empty and made only of
// characters that need no quoting in jail.conf, sh or fstab.
func safeValue(field, s string) (string, error) {
	if !safeValueRE.MatchString(s) {
		return "", fmt.Errorf("render: %s %q contains unsupported characters", field, s)
	}
	return s, nil
}

// quoted returns s in double quotes after safeValue.
func quoted(field, s string) (string, error) {
	v, err := safeValue(field, s)
	if err != nil {
		return "", err
	}
	return `"` + v + `"`, nil
}

// builder collects lines and the first error.
type builder struct {
	sb    strings.Builder
	err   error
	n     int    // the lines written so far
	rules []Rule // the structured form of the filter rules among them
}

func (b *builder) line(format string, args ...any) {
	fmt.Fprintf(&b.sb, format, args...)
	b.sb.WriteByte('\n')
	b.n++
}

// rule writes a line and records what the rule on it matches.
func (b *builder) rule(r Rule, format string, args ...any) {
	if r.Kind == "" {
		r.Kind = RuleFilter
	}
	r.Line = b.n
	b.rules = append(b.rules, r)
	b.line(format, args...)
}

func (b *builder) fail(err error) {
	if b.err == nil && err != nil {
		b.err = err
	}
}

func (b *builder) result() (string, error) {
	if b.err != nil {
		return "", b.err
	}
	return b.sb.String(), nil
}

// Header is the first line of every generated file.
const Header = "# Managed by JailOps. Do not edit; changes are overwritten."
