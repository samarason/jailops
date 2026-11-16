package cli

import (
	"bytes"
	"encoding/csv"
	"encoding/json"
	"fmt"
	"io"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"gopkg.in/yaml.v3"
)

type format string

const (
	fmtTable format = "table"
	// fmtWide is a table with every column, on a terminal too; it is parsed
	// into fmtTable plus app.wide, so every other command treats it as table.
	fmtWide format = "wide"
	// fmtCompact is the plain table of a pipe (space-aligned, no borders,
	// every column) on a terminal too; it is parsed into fmtTable plus
	// app.compact.
	fmtCompact format = "compact"
	fmtJSON    format = "json"
	fmtYAML    format = "yaml"
	fmtName    format = "name"
	fmtCSV     format = "csv"
)

var formatNames = []string{"table", "wide", "compact", "json", "yaml", "name", "csv"}

func parseFormat(s string) (format, error) {
	switch format(s) {
	case "", fmtTable:
		return fmtTable, nil
	case fmtWide, fmtCompact, fmtJSON, fmtYAML, fmtName, fmtCSV:
		return format(s), nil
	}
	return "", usagef("unknown output format %q (use table, wide, compact, json, yaml, name or csv)", s)
}

// styleFn returns an ANSI SGR code ("32") for a table cell, or "" for none.
type styleFn func(col int, val string) string

// pretty reports whether tables are drawn for a person reading a terminal:
// with borders, and in their short form unless -o wide asks for every column.
// Anything else (a pipe, a file, --no-headers, -o compact) gets the plain
// form that scripts cut and the golden tests expect.
func (a *app) pretty() bool {
	return a.format == fmtTable && !a.noHeaders && !a.compact && a.env.IsTTY(a.env.Stdout)
}

// emit prints v in the selected format. table builds the human form and names
// the list of names for -o name; either may be nil.
func (a *app) emit(v any, style styleFn, table func() ([]string, [][]string), names func() []string) error {
	return a.emitList(v, style, table, nil, names)
}

// emitList is emit for a table that may lose columns on a narrow terminal:
// drop lists them, least important first.
func (a *app) emitList(v any, style styleFn, table func() ([]string, [][]string), drop []int, names func() []string) error {
	w := a.env.Stdout
	switch a.format {
	case fmtJSON:
		enc := json.NewEncoder(w)
		enc.SetEscapeHTML(false)
		enc.SetIndent("", "  ")
		if err := enc.Encode(v); err != nil {
			return err
		}
	case fmtYAML:
		b, err := toYAML(v)
		if err != nil {
			return err
		}
		_, _ = w.Write(b)
	case fmtName:
		if names == nil {
			return usagef("-o name is not available for this command")
		}
		for _, n := range names() {
			fprintln(w, n)
		}
	case fmtCSV:
		if table == nil {
			return usagef("-o csv is not available for this command")
		}
		h, rows := table()
		cw := csv.NewWriter(w)
		if !a.noHeaders {
			_ = cw.Write(h)
		}
		for _, r := range rows {
			_ = cw.Write(r)
		}
		cw.Flush()
		return cw.Error()
	default:
		if table == nil {
			b, err := toYAML(v)
			if err != nil {
				return err
			}
			_, _ = w.Write(b)
			return nil
		}
		h, rows := table()
		if len(rows) == 0 {
			msg := "No resources found."
			if a.empty != "" {
				msg = a.empty
			}
			fprintln(a.env.Stderr, msg)
			return nil
		}
		if a.pretty() {
			a.printBoxed(w, h, rows, style, drop)
			return nil
		}
		a.printTable(w, h, rows, style)
	}
	return nil
}

// printBoxed draws a table with thin borders for a terminal. A cell may hold
// several lines; its row grows as tall as the cell. When the terminal is
// narrower than the table, the columns named in drop are left out, first
// first, until it fits; a cell is never cut.
func (a *app) printBoxed(w io.Writer, head []string, rows [][]string, style styleFn, drop []int) {
	color := style != nil && a.colorOn(w)
	for i := range rows {
		for len(rows[i]) < len(head) {
			rows[i] = append(rows[i], "")
		}
	}
	for _, r := range rows {
		for i, c := range r {
			r[i] = termText(c, true)
		}
	}
	lines := func(cell string) []string { return strings.Split(cell, "\n") }
	width := make([]int, len(head))
	for i, h := range head {
		width[i] = utf8.RuneCountInString(h)
	}
	for _, r := range rows {
		for i, c := range r {
			for _, l := range lines(c) {
				width[i] = max(width[i], utf8.RuneCountInString(l))
			}
		}
	}
	keep := make([]bool, len(head))
	for i := range keep {
		keep[i] = true
	}
	total := func() int {
		n := 1
		for i, w := range width {
			if keep[i] {
				n += w + 3
			}
		}
		return n
	}
	if _, cols, ok := a.env.TermSize(w); ok && cols > 0 {
		for _, d := range drop {
			if total() <= int(cols) {
				break
			}
			if d >= 0 && d < len(keep) {
				keep[d] = false
			}
		}
	}
	rule := func(l, m, r string) {
		var b strings.Builder
		b.WriteString(l)
		first := true
		for i, wd := range width {
			if !keep[i] {
				continue
			}
			if !first {
				b.WriteString(m)
			}
			first = false
			b.WriteString(strings.Repeat("─", wd+2))
		}
		b.WriteString(r)
		fprintln(w, b.String())
	}
	line := func(cells []string, hdr bool) {
		height := 1
		for i, c := range cells {
			if keep[i] {
				height = max(height, len(lines(c)))
			}
		}
		for n := range height {
			var b strings.Builder
			b.WriteString("│")
			for i, c := range cells {
				if !keep[i] {
					continue
				}
				text := ""
				if ls := lines(c); n < len(ls) {
					text = ls[n]
				}
				pad := width[i] - utf8.RuneCountInString(text)
				if color && !hdr {
					if code := style(i, text); code != "" {
						text = "\x1b[" + code + "m" + text + "\x1b[0m"
					}
				}
				b.WriteString(" " + text + strings.Repeat(" ", pad) + " │")
			}
			fprintln(w, colored(b.String()))
		}
	}
	rule("┌", "┬", "┐")
	line(head, true)
	rule("├", "┼", "┤")
	for _, r := range rows {
		line(r, false)
	}
	rule("└", "┴", "┘")
}

func (a *app) printTable(w io.Writer, head []string, rows [][]string, style styleFn) {
	color := style != nil && a.colorOn(w)
	for _, r := range rows {
		for i, c := range r {
			r[i] = termText(c, true)
		}
	}
	width := make([]int, len(head))
	for i, h := range head {
		width[i] = utf8.RuneCountInString(h)
	}
	for _, r := range rows {
		for i, c := range r {
			if i < len(width) {
				width[i] = max(width[i], utf8.RuneCountInString(c))
			}
		}
	}
	line := func(cells []string, hdr bool) {
		var b strings.Builder
		for i, c := range cells {
			cell := c
			pad := width[i] - utf8.RuneCountInString(c)
			if color && !hdr {
				if code := style(i, c); code != "" {
					cell = "\x1b[" + code + "m" + c + "\x1b[0m"
				}
			}
			b.WriteString(cell)
			if i < len(cells)-1 {
				b.WriteString(strings.Repeat(" ", pad+3))
			}
		}
		fprintln(w, colored(b.String()))
	}
	if !a.noHeaders {
		line(head, true)
	}
	for _, r := range rows {
		for len(r) < len(head) {
			r = append(r, "")
		}
		line(r, false)
	}
}

// stateStyle colours a power state cell in column col.
func stateStyle(col int) styleFn {
	return func(c int, v string) string {
		if c != col {
			return ""
		}
		switch v {
		case "running", "online", "success", "OK", "ok", "PASS":
			return "32"
		case "stopped", "pending", "offline":
			return "90"
		case "starting", "stopping", "running...", "WARN", "locked":
			return "33"
		case "error", "failure", "FAIL":
			return "31"
		}
		return ""
	}
}

// toYAML encodes any JSON-serialisable value as YAML with the field order and
// names of its JSON form (the wire types carry json tags only).
func toYAML(v any) ([]byte, error) {
	raw, err := json.Marshal(v)
	if err != nil {
		return nil, err
	}
	n, err := jsonToNode(raw)
	if err != nil {
		return nil, err
	}
	var buf bytes.Buffer
	enc := yaml.NewEncoder(&buf)
	enc.SetIndent(2)
	if err := enc.Encode(n); err != nil {
		return nil, err
	}
	_ = enc.Close()
	return buf.Bytes(), nil
}

func jsonToNode(raw []byte) (*yaml.Node, error) {
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	return decodeNode(dec)
}

func decodeNode(dec *json.Decoder) (*yaml.Node, error) {
	t, err := dec.Token()
	if err != nil {
		return nil, err
	}
	switch tv := t.(type) {
	case json.Delim:
		switch tv {
		case '{':
			n := &yaml.Node{Kind: yaml.MappingNode, Tag: "!!map"}
			for dec.More() {
				kt, err := dec.Token()
				if err != nil {
					return nil, err
				}
				val, err := decodeNode(dec)
				if err != nil {
					return nil, err
				}
				if val.Kind == yaml.MappingNode && len(val.Content) == 0 {
					continue // an empty object adds nothing to the human form
				}
				n.Content = append(n.Content, &yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: kt.(string)}, val)
			}
			_, err = dec.Token()
			return n, err
		case '[':
			n := &yaml.Node{Kind: yaml.SequenceNode, Tag: "!!seq"}
			for dec.More() {
				val, err := decodeNode(dec)
				if err != nil {
					return nil, err
				}
				n.Content = append(n.Content, val)
			}
			_, err = dec.Token()
			return n, err
		}
	case string:
		n := &yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: tv}
		if strings.Contains(tv, "\n") {
			n.Style = yaml.LiteralStyle
		}
		return n, nil
	case json.Number:
		tag := "!!int"
		if strings.ContainsAny(tv.String(), ".eE") {
			tag = "!!float"
		}
		return &yaml.Node{Kind: yaml.ScalarNode, Tag: tag, Value: tv.String()}, nil
	case bool:
		return &yaml.Node{Kind: yaml.ScalarNode, Tag: "!!bool", Value: fmt.Sprint(tv)}, nil
	case nil:
		return &yaml.Node{Kind: yaml.ScalarNode, Tag: "!!null", Value: "null"}, nil
	}
	return nil, fmt.Errorf("unexpected JSON token %v", t)
}

// humanization -------------------------------------------------------------

func humanBytes(n int64) string {
	const unit = 1024
	if n < unit {
		return fmt.Sprintf("%d B", n)
	}
	div, exp := int64(unit), 0
	for m := n / unit; m >= unit; m /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %ciB", float64(n)/float64(div), "KMGTPE"[exp])
}

// sizeText shows a size the server stores as bytes ("4294967296") in the largest binary unit that divides it ("4G");
// anything else is shown as it is.
func sizeText(s string) string {
	n, err := strconv.ParseUint(s, 10, 64)
	if err != nil || n == 0 {
		return s
	}
	for i := 5; i >= 1; i-- {
		if u := uint64(1) << (10 * i); n%u == 0 {
			return strconv.FormatUint(n/u, 10) + string("KMGTP"[i-1])
		}
	}
	return s
}

func age(now, t time.Time) string {
	if t.IsZero() {
		return "-"
	}
	d := now.Sub(t)
	switch {
	case d < 0:
		return "0s"
	case d < time.Minute:
		return fmt.Sprintf("%ds", int(d.Seconds()))
	case d < time.Hour:
		return fmt.Sprintf("%dm", int(d.Minutes()))
	case d < 48*time.Hour:
		return fmt.Sprintf("%dh", int(d.Hours()))
	}
	return fmt.Sprintf("%dd", int(d.Hours()/24))
}

func dash(s string) string {
	if s == "" {
		return "-"
	}
	return s
}

func joinOrDash(s []string) string { return dash(strings.Join(s, ",")) }

// linesOrDash puts each value on a line of its own, for a cell of a boxed table.
func linesOrDash(s []string) string { return dash(strings.Join(s, "\n")) }

// imageWithGen names an image reference with the generation a jail runs and, for a release, the FreeBSD patch level
// of that generation: "freebsd-15-1 (g3, p6)". A reference pinned to that generation shows only the patch level.
func imageWithGen(ref, gen, freebsd string) string {
	var extra []string
	short := gen
	if img, n, ok := strings.Cut(gen, "#"); ok && img == imageBase(ref) {
		short = n
	}
	if gen != "" && ref != gen && !strings.HasSuffix(ref, "#"+short) {
		extra = append(extra, short)
	}
	if p := patchLevel(freebsd); p != "" {
		extra = append(extra, p)
	}
	if len(extra) == 0 {
		return ref
	}
	return ref + " (" + strings.Join(extra, ", ") + ")"
}

// patchLevel is "p6" of "15.1-RELEASE-p6"; "" for a release without a patch, a snapshot or nothing.
func patchLevel(freebsd string) string {
	if _, p, ok := strings.Cut(freebsd, "-RELEASE-"); ok {
		return p
	}
	return ""
}

// paint wraps s, cleaned, in the colour of a table cell when colour is on for w.
func (a *app) paint(w io.Writer, style styleFn, s string) colored {
	s = termText(s, false)
	if !a.colorOn(w) {
		return colored(s)
	}
	if code := style(0, s); code != "" {
		return colored("\x1b[" + code + "m" + s + "\x1b[0m")
	}
	return colored(s)
}
