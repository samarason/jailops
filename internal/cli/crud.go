package cli

import (
	"context"
	"errors"
	"fmt"
	"iter"
	"os"
	"os/exec"
	"path"
	"slices"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"jailops.net/jailops/sdk"
	"jailops.net/jailops/sdk/api"
)

// kindDesc describes one resource kind to the generic list, show, create,
// edit and delete commands.
type kindDesc[T any] struct {
	noun, plural string
	kind         api.Kind
	meta         func(*T) *api.ObjectMeta
	specOf       func(*T) any
	// parse builds an object from a document (envelope or bare spec).
	parse func(meta api.ObjectMeta, doc map[string]any, name string) (T, error)
	// setSpec copies the editable parts of src into dst.
	setSpec func(dst *T, src T)

	list   func(ctx context.Context, c *sdk.Client, opts ...sdk.ListOption) iter.Seq2[T, error]
	get    func(ctx context.Context, c *sdk.Client, name string) (T, string, error)
	update func(ctx context.Context, c *sdk.Client, name string, v T, etag string) (T, error)
	// create returns a handle when the server answered asynchronously.
	create func(ctx context.Context, c *sdk.Client, v T) (opHandle, T, error)
	del    func(ctx context.Context, c *sdk.Client, name string) (opHandle, error)
	// rename is set for a kind that can be renamed: crudCommands adds "rename" and edit renames when the name
	// of the document changed.
	rename renameFn
	// renameLong is the help of its rename command.
	renameLong string

	head  []string
	row   func(now time.Time, x T) []string
	style styleFn
	// brief is the short form of the list on a terminal; nil shows head and
	// row there too. -o wide always shows head and row.
	brief *listView[T]
	// show prints the human form of one object; nil prints YAML.
	show func(a *app, x T) error
	// warnings are what the server said about a created object (nil for a kind that has none); each is printed
	// on standard error after the confirmation.
	warnings func(x T) []string
	// updated prints, on standard error, what the server said about an updated object (nil for a kind that says nothing).
	updated func(a *app, x T)
	// filters registers extra list flags and returns the function that checks
	// them once they are parsed and gives the predicate.
	filters func(cmd *cobra.Command) func() (func(x T) bool, error)
	// afterCreate registers extra flags of "create" and returns what runs
	// once an object is created (nil for nothing).
	afterCreate func(cmd *cobra.Command) func(ctx context.Context, name string) error
	// beforeDelete registers extra flags of "delete" and returns what runs
	// before an object is deleted (nil for nothing).
	beforeDelete func(cmd *cobra.Command) func(ctx context.Context, name string) error
	// targets registers the selector flags of a command that acts on several
	// objects and returns the resolver of the names: the arguments, or the
	// objects a selector matches (bulk). nil means the arguments only.
	targets func(cmd *cobra.Command) func(ctx context.Context, args []string) (names []string, bulk bool, err error)
	// noSet is set for a kind that has a "set" of its own
	noSet bool
	// revoke is set for a kind of credentials: the command that ends one is "revoke", not "delete"
	revoke bool
	// loss is set for a kind whose delete destroys data: it says what deleting one object destroys, read from
	// the server before anything is deleted, or refuses a delete that cannot go ahead. Such a delete needs the
	// typed name or --confirm-data-loss; -y does not answer it.
	loss func(cmd *cobra.Command, ctx context.Context, c *sdk.Client, name string) (string, error)
	// prepare fills in what the server can tell before an object built from flags is created, such as the
	// defaults of a jail (nil for nothing).
	prepare func(ctx context.Context, c *sdk.Client, x *T) error
	// emptyHint is the command that creates the first object, for the message of an empty list ("" for the
	// kind's create NAME, when it has one).
	emptyHint string
	// emptyHintFrom computes emptyHint with what the server says (nil for the fixed one).
	emptyHintFrom func(ctx context.Context, c *sdk.Client) string
}

func (d *kindDesc[T]) name(x T) string { return d.meta(&x).Name }

// listView is one tabular form of a list. A cell of row may hold several
// lines ("\n"); the boxed table of a terminal grows the row, the plain form
// is never given such a view.
type listView[T any] struct {
	head  []string
	row   func(now time.Time, x T) []string
	style styleFn
	// drop names the columns to leave out, least important first, when a
	// terminal is too narrow for the whole table.
	drop []int
}

// view picks the form of the list for the current output.
func (d *kindDesc[T]) view(a *app) listView[T] {
	if d.brief != nil && !a.wide && a.pretty() {
		return *d.brief
	}
	return d.full()
}

// full is the form with every column, the one -o wide shows.
func (d *kindDesc[T]) full() listView[T] {
	return listView[T]{head: d.head, row: d.row, style: d.style}
}

// newDesc builds the parts of a descriptor that follow from the types.
func newDesc[T, S any](noun, plural string, kind api.Kind, meta func(*T) *api.ObjectMeta, spec func(*T) *S) kindDesc[T] {
	d := kindDesc[T]{noun: noun, plural: plural, kind: kind, meta: meta}
	d.specOf = func(x *T) any { return spec(x) }
	d.parse = func(m api.ObjectMeta, doc map[string]any, name string) (T, error) {
		var x T
		pm, ps, err := parseObject[S](doc, kind, name)
		if err != nil {
			return x, err
		}
		_ = m
		*meta(&x) = pm
		*spec(&x) = ps
		return x, nil
	}
	d.setSpec = func(dst *T, src T) {
		*spec(dst) = *spec(&src)
		meta(dst).Labels = meta(&src).Labels
	}
	return d
}

// fromResource wires the client calls of a plain Resource.
func fromResource[T any](d *kindDesc[T], r func(*sdk.Client) *sdk.Resource[T]) {
	d.list = func(ctx context.Context, c *sdk.Client, o ...sdk.ListOption) iter.Seq2[T, error] {
		return r(c).List(ctx, o...)
	}
	d.get = func(ctx context.Context, c *sdk.Client, n string) (T, string, error) { return r(c).GetETag(ctx, n) }
	d.update = func(ctx context.Context, c *sdk.Client, n string, v T, etag string) (T, error) {
		return r(c).Update(ctx, n, v, etag)
	}
	d.create = func(ctx context.Context, c *sdk.Client, v T) (opHandle, T, error) {
		out, err := r(c).Create(ctx, v)
		return nil, out, err
	}
	d.del = func(ctx context.Context, c *sdk.Client, n string) (opHandle, error) {
		return nil, r(c).Delete(ctx, n)
	}
}

func collect[T any](seq iter.Seq2[T, error]) ([]T, error) {
	var out []T
	for v, err := range seq {
		if err != nil {
			return nil, err
		}
		out = append(out, v)
	}
	return out, nil
}

func labelOpts(labels []string) ([]sdk.ListOption, error) {
	var out []sdk.ListOption
	for _, l := range labels {
		k, v, ok := strings.Cut(l, "=")
		if !ok || k == "" {
			return nil, usagef("label %q must be key=value", l)
		}
		out = append(out, sdk.Label(k, v))
	}
	return out, nil
}

// article is "a" or "an" for a noun, as in "Create an image".
func article(noun string) string {
	// "user" starts with a vowel and is said with a consonant
	if noun != "" && !strings.HasPrefix(noun, "user") && strings.ContainsRune("aeiou", rune(noun[0])) {
		return "an"
	}
	return "a"
}

// completion ---------------------------------------------------------------

type completer = func(*cobra.Command, []string, string) ([]string, cobra.ShellCompDirective)

// completeWith completes an argument from a list on the server, which may
// depend on the arguments already given. A shell is waiting: a server that
// does not answer within a moment, or any error, just yields no names and
// never a message. Names already on the line are left out.
func (a *app) completeWith(list func(ctx context.Context, c *sdk.Client, args []string) ([]string, error)) completer {
	return func(cmd *cobra.Command, args []string, _ string) ([]string, cobra.ShellCompDirective) {
		ctx, cancel := context.WithTimeout(cmd.Context(), completionTimeout)
		defer cancel()
		c, err := a.connect(ctx)
		if err != nil {
			return nil, cobra.ShellCompDirectiveNoFileComp
		}
		names, err := list(ctx, c, args)
		if err != nil {
			return nil, cobra.ShellCompDirectiveNoFileComp
		}
		names = slices.DeleteFunc(names, func(n string) bool { return slices.Contains(args, n) })
		return names, cobra.ShellCompDirectiveNoFileComp
	}
}

// completeNames completes every argument from one list on the server.
func (a *app) completeNames(list func(ctx context.Context, c *sdk.Client) ([]string, error)) completer {
	return a.completeWith(func(ctx context.Context, c *sdk.Client, _ []string) ([]string, error) { return list(ctx, c) })
}

func completeKind[T any](a *app, d *kindDesc[T]) completer {
	return a.completeNames(func(ctx context.Context, c *sdk.Client) ([]string, error) {
		items, err := collect(d.list(ctx, c))
		var n []string
		for _, it := range items {
			n = append(n, d.name(it))
		}
		return n, err
	})
}

// completeArgs gives each positional argument its own completion; the last
// one serves every further argument.
func completeArgs(fns ...completer) completer {
	return func(cmd *cobra.Command, args []string, p string) ([]string, cobra.ShellCompDirective) {
		return fns[min(len(args), len(fns)-1)](cmd, args, p)
	}
}

// completeNone offers nothing, not even files.
func completeNone(*cobra.Command, []string, string) ([]string, cobra.ShellCompDirective) {
	return nil, cobra.ShellCompDirectiveNoFileComp
}

// completeFiles leaves the argument to the shell's own file completion.
func completeFiles(*cobra.Command, []string, string) ([]string, cobra.ShellCompDirective) {
	return nil, cobra.ShellCompDirectiveDefault
}

// enumFlag completes a flag from a fixed list of values.
func enumFlag(cmd *cobra.Command, name string, values ...string) {
	_ = cmd.RegisterFlagCompletionFunc(name, func(*cobra.Command, []string, string) ([]string, cobra.ShellCompDirective) {
		return values, cobra.ShellCompDirectiveNoFileComp
	})
}

// list ---------------------------------------------------------------------

// columnName is the name a column is addressed by: "last-seen" for "LAST SEEN".
func columnName(head string) string {
	return strings.ReplaceAll(strings.ToLower(head), " ", "-")
}

func columnNames(head []string) []string {
	var out []string
	for _, h := range head {
		if h != "" {
			out = append(out, columnName(h))
		}
	}
	return out
}

func columnIndex(head []string, name string) (int, error) {
	for i, h := range head {
		if h != "" && columnName(h) == strings.ToLower(strings.TrimSpace(name)) {
			return i, nil
		}
	}
	return 0, usagef("unknown column %q (columns: %s)", name, strings.Join(columnNames(head), ", "))
}

// cellLess orders two cells of a table: numbers and ages ("3h", "10d") by
// value, everything else by text.
func cellLess(x, y string) bool {
	if a, ok := cellValue(x); ok {
		if b, ok := cellValue(y); ok && a != b {
			return a < b
		}
	}
	return x < y
}

func cellValue(s string) (float64, bool) {
	if n, err := strconv.ParseFloat(s, 64); err == nil {
		return n, true
	}
	unit := map[byte]float64{'s': 1, 'm': 60, 'h': 3600, 'd': 86400}
	if l := len(s); l > 1 {
		if m, ok := unit[s[l-1]]; ok {
			if n, err := strconv.Atoi(s[:l-1]); err == nil {
				return float64(n) * m, true
			}
		}
	}
	return 0, false
}

func matchesAny(patterns []string, name string) bool {
	if len(patterns) == 0 {
		return true
	}
	for _, p := range patterns {
		if ok, _ := path.Match(p, name); ok {
			return true
		}
	}
	return false
}

// columns are the names of the columns a list of the kind has, in -o wide order, then those only its short form
// on a terminal has.
func (d *kindDesc[T]) columns() []string {
	out := columnNames(d.head)
	if d.brief != nil {
		for _, c := range columnNames(d.brief.head) {
			if !slices.Contains(out, c) {
				out = append(out, c)
			}
		}
	}
	return out
}

// viewFor picks the form of the list that has every column asked for: the one -o wide shows, else the short one.
func (d *kindDesc[T]) viewFor(names []string) (listView[T], error) {
	has := func(head []string) bool {
		for _, n := range names {
			if _, err := columnIndex(head, n); err != nil {
				return false
			}
		}
		return true
	}
	switch {
	case has(d.head):
		return d.full(), nil
	case d.brief != nil && has(d.brief.head):
		return *d.brief, nil
	}
	for _, n := range names {
		if !slices.Contains(d.columns(), strings.ToLower(strings.TrimSpace(n))) {
			return listView[T]{}, usagef("unknown column %q (columns: %s)", n, strings.Join(d.columns(), ", "))
		}
	}
	return listView[T]{}, usagef("columns %s are not in one table (columns of -o wide: %s)", strings.Join(names, ", "), strings.Join(columnNames(d.head), ", "))
}

// listExample is the example of -c and --sort, with columns the kind has.
func listExample(head []string) string {
	cols := columnNames(head)
	if slices.Contains(cols, "age") {
		return "-c name,age --sort age"
	}
	other := "name"
	for _, c := range cols {
		if c != "name" {
			other = c
			break
		}
	}
	return "-c name," + other + " --sort name"
}

// addList adds "list".
func addList[T any](a *app, parent *cobra.Command, d *kindDesc[T], extraExample string) {
	var labels, columns []string
	var sortBy string
	var keep func() (func(T) bool, error)
	cmd := &cobra.Command{
		Use:     "list [PATTERN...]",
		Aliases: []string{"ls"},
		Short:   "List " + d.plural,
		Long: "List " + d.plural + ` known to the server, optionally filtered by label (-l, also
--selector) or by name patterns such as 'web*'. The default output is a table: -c
picks its columns and --sort orders its rows (columns: ` + strings.Join(d.columns(), ", ") + `).
-o json and -o yaml print the full objects, -o name the names only, -o csv the table as CSV.`,
		Example:           "jailops " + "@P@" + " list\njailops " + "@P@" + " list 'web*' " + listExample(d.head) + "\njailops " + "@P@" + " list -l env=prod -o name" + extraExample,
		Args:              cobra.ArbitraryArgs,
		ValidArgsFunction: completeKind(a, d),
		RunE: func(cmd *cobra.Command, args []string) error {
			for _, p := range args {
				if _, err := path.Match(p, ""); err != nil {
					return usagef("bad name pattern %q", p)
				}
			}
			var pred func(T) bool
			if keep != nil {
				var err error
				if pred, err = keep(); err != nil {
					return err
				}
			}
			opts, err := labelOpts(labels)
			if err != nil {
				return err
			}
			v := d.view(a)
			if len(columns) > 0 || sortBy != "" {
				asked := slices.Clone(columns)
				if sortBy != "" {
					asked = append(asked, sortBy)
				}
				if v, err = d.viewFor(asked); err != nil {
					return err
				}
			}
			sortCol := -1
			if sortBy != "" {
				if sortCol, err = columnIndex(v.head, sortBy); err != nil {
					return err
				}
			}
			var pick []int
			for _, c := range columns {
				i, err := columnIndex(v.head, c)
				if err != nil {
					return err
				}
				pick = append(pick, i)
			}
			c, err := a.connect(cmd.Context())
			if err != nil {
				return err
			}
			items, err := collect(d.list(cmd.Context(), c, opts...))
			if err != nil {
				return err
			}
			total := len(items)
			kept := items[:0]
			for _, it := range items {
				if (pred == nil || pred(it)) && matchesAny(args, d.name(it)) {
					kept = append(kept, it)
				}
			}
			items = kept
			rows := make([][]string, len(items))
			for i, it := range items {
				rows[i] = v.row(a.env.Now(), it)
			}
			if sortCol >= 0 {
				order := make([]int, len(items))
				for i := range order {
					order[i] = i
				}
				sort.SliceStable(order, func(i, j int) bool { return cellLess(rows[order[i]][sortCol], rows[order[j]][sortCol]) })
				sortedItems, sortedRows := make([]T, len(items)), make([][]string, len(rows))
				for i, o := range order {
					sortedItems[i], sortedRows[i] = items[o], rows[o]
				}
				items, rows = sortedItems, sortedRows
			}
			head, style, drop := v.head, v.style, v.drop
			if len(pick) > 0 {
				head = make([]string, len(pick))
				for i, p := range pick {
					head[i] = v.head[p]
				}
				for r, row := range rows {
					cells := make([]string, len(pick))
					for i, p := range pick {
						cells[i] = row[p]
					}
					rows[r] = cells
				}
				drop = nil
				if v.style != nil {
					style = func(col int, val string) string { return v.style(pick[col], val) }
				}
			}
			if len(items) == 0 {
				hint := d.emptyHint
				if d.emptyHintFrom != nil {
					hint = d.emptyHintFrom(cmd.Context(), c)
				}
				a.empty = emptyMessage(cmd, d.plural, hint, total > 0 || len(args) > 0 || len(labels) > 0, a)
			}
			return a.emitList(nonNil(items), style, func() ([]string, [][]string) { return head, rows }, drop, func() []string {
				var n []string
				for _, it := range items {
					n = append(n, d.name(it))
				}
				return n
			})
		},
	}
	cmd.Flags().StringArrayVarP(&labels, "label", "l", nil, "only objects with this label, key=value (repeatable)")
	cmd.Flags().StringSliceVarP(&columns, "columns", "c", nil, "columns of the table, comma separated: "+strings.Join(d.columns(), ", "))
	cmd.Flags().StringVar(&sortBy, "sort", "", "order the rows by this column")
	enumFlag(cmd, "columns", d.columns()...)
	enumFlag(cmd, "sort", d.columns()...)
	if d.filters != nil {
		keep = d.filters(cmd)
	}
	parent.AddCommand(cmd)
}

// emptyMessage is what an empty list says: the kind, the project for a kind that lives in one, and the command
// that creates the first one. filtered is true when patterns or filters left everything out.
func emptyMessage(cmd *cobra.Command, plural, hint string, filtered bool, a *app) string {
	where := ""
	if projectScoped(cmd) && a.conn != nil {
		where = " in project " + a.conn.CurrentProject()
	}
	if filtered {
		return "No " + plural + where + " match."
	}
	if hint == "" {
		if c, _, err := cmd.Parent().Find([]string{"create"}); err == nil && c != cmd.Parent() {
			hint = c.CommandPath() + " NAME"
		}
	}
	msg := "No " + plural + where + "."
	if hint != "" {
		msg += " Create one with: " + hint
	}
	return msg
}

func nonNil[T any](s []T) []T {
	if s == nil {
		return []T{}
	}
	return s
}

// show ---------------------------------------------------------------------

// addShow adds "show".
func addShow[T any](a *app, parent *cobra.Command, d *kindDesc[T]) {
	path := "@P@"
	parent.AddCommand(&cobra.Command{
		Use:               "show NAME",
		Aliases:           []string{"get"},
		Short:             "Show one " + d.noun,
		Long:              "Show one " + d.noun + " with its specification and, where the server reports it, its observed status.\n-o json and -o yaml print the complete object.",
		Example:           "jailops " + path + " show NAME\njailops " + path + " show NAME -o yaml",
		Args:              cobra.ExactArgs(1),
		ValidArgsFunction: completeKind(a, d),
		RunE: func(cmd *cobra.Command, args []string) error {
			c, err := a.connect(cmd.Context())
			if err != nil {
				return err
			}
			x, _, err := d.get(cmd.Context(), c, args[0])
			if err != nil {
				return err
			}
			if a.format == fmtTable && d.show != nil {
				return d.show(a, x)
			}
			return a.emit(x, nil, nil, func() []string { return []string{d.name(x)} })
		},
	})
}

// showObject prints the human form of one object: a short header (with the
// extra lines a kind adds), then the specification next to the observed
// status.
func (a *app) showObject(m api.ObjectMeta, extra []string, spec, status any) error {
	w := a.env.Stdout
	fprintf(w, "Name:        %s\n", m.Name)
	fprintf(w, "UUID:        %s\n", dash(m.UUID))
	fprintf(w, "Generation:  %d\n", m.Generation)
	fprintf(w, "Age:         %s\n", age(a.env.Now(), m.CreatedAt))
	for _, l := range extra {
		fprintln(w, l)
	}
	if len(m.Labels) > 0 {
		var l []string
		for _, k := range sortedKeys(m.Labels) {
			l = append(l, k+"="+m.Labels[k])
		}
		fprintf(w, "Labels:      %s\n", strings.Join(l, ", "))
	}
	fprintln(w)
	sb, err := toYAML(spec)
	if err != nil {
		return err
	}
	st, err := toYAML(status)
	if err != nil {
		return err
	}
	sideBySide(w, "SPEC", string(sb), "STATUS", string(st))
	return nil
}

// create -------------------------------------------------------------------

// addCreate adds "create". flagBuild registers flags and returns the builder
// used when no file is given; it may be nil when only -f is supported.
func addCreate[T any](a *app, parent *cobra.Command, d *kindDesc[T], long, example string, flagBuild func(*cobra.Command) func(name string) (T, error)) {
	var file string
	cmd := &cobra.Command{
		Use:   "create [NAME]",
		Short: "Create " + article(d.noun) + " " + d.noun,
		Long: long + `

With -f the object comes from a YAML or JSON file ("-" reads standard input).
The file may use the declarative envelope (apiVersion, kind, metadata, spec) or
be a bare spec, in which case NAME is required. A file may hold several
documents; each one is created in order.`,
		Example: example,
		Args:    cobra.MaximumNArgs(1),
	}
	var build func(string) (T, error)
	if flagBuild != nil {
		build = flagBuild(cmd)
	}
	var after func(context.Context, string) error
	if d.afterCreate != nil {
		after = d.afterCreate(cmd)
	}
	cmd.Flags().StringVarP(&file, "file", "f", "", "create from this YAML or JSON file, or - for standard input")
	cmd.RunE = func(cmd *cobra.Command, args []string) error {
		var objs []T
		nameArg := ""
		if len(args) == 1 {
			nameArg = args[0]
		}
		if file != "" {
			b, err := a.readInput(file)
			if err != nil {
				return err
			}
			docs, err := readDocs(b)
			if err != nil {
				return err
			}
			if nameArg != "" && len(docs) > 1 {
				return usagef("NAME cannot be combined with a file of several documents")
			}
			for _, doc := range docs {
				x, err := d.parse(api.ObjectMeta{}, doc, nameArg)
				if err != nil {
					return err
				}
				objs = append(objs, x)
			}
		} else {
			if nameArg == "" {
				return usagef("NAME is required (or use -f FILE)")
			}
			if build == nil {
				return usagef("%s %s is created from a file: use -f FILE", article(d.noun), d.noun)
			}
			x, err := build(nameArg)
			if err != nil {
				return err
			}
			if d.prepare != nil {
				c, err := a.connect(cmd.Context())
				if err != nil {
					return err
				}
				if err := d.prepare(cmd.Context(), c, &x); err != nil {
					return err
				}
			}
			objs = append(objs, x)
		}
		for _, x := range objs {
			name := d.name(x)
			if ok, err := a.dry("create "+d.noun+" "+name, document(d.kind, *d.meta(&x), d.specOf(&x))); ok || err != nil {
				if err != nil {
					return err
				}
			} else {
				c, err := a.connect(cmd.Context())
				if err != nil {
					return err
				}
				h, out, err := d.create(cmd.Context(), c, x)
				if err != nil {
					return err
				}
				if err := a.finishOp(cmd.Context(), h, d.noun, name, "created", out); err != nil {
					return err
				}
				createWarnings(a, d, out)
			}
			if after != nil {
				if err := after(cmd.Context(), name); err != nil {
					return err
				}
			}
		}
		return nil
	}
	parent.AddCommand(cmd)
}

// createWarnings prints what the server warned about a created object, on standard error, after the confirmation.
func createWarnings[T any](a *app, d *kindDesc[T], x T) {
	if d.warnings == nil {
		return
	}
	for _, w := range d.warnings(x) {
		fprintf(a.env.Stderr, "warning: %s\n", w)
	}
}

// delete -------------------------------------------------------------------

// addDelete adds "delete".
func addDelete[T any](a *app, parent *cobra.Command, d *kindDesc[T]) {
	path := "@P@"
	verb, past, aliases := "delete", "deleted", []string{"rm"}
	if d.revoke {
		verb, past, aliases = "revoke", "revoked", nil
	}
	Verb := strings.ToUpper(verb[:1]) + verb[1:]
	cmd := &cobra.Command{
		Use:               verb + " NAME...",
		Aliases:           aliases,
		Short:             Verb + " " + d.plural,
		Long:              Verb + " one or more " + d.plural + ". The server refuses when another object still uses them.\nThe command asks for confirmation unless -y is given.",
		Example:           "jailops " + path + " " + verb + " NAME\njailops " + path + " " + verb + " -y NAME1 NAME2",
		Args:              cobra.MinimumNArgs(1),
		ValidArgsFunction: completeKind(a, d),
	}
	var confirmLoss bool
	if d.loss != nil {
		cmd.Long = "Delete one or more " + d.plural + ` with everything they hold. This destroys data: the files
and the snapshots go with the ` + d.noun + `, and nothing brings them back.
Before anything is deleted the command shows what each delete destroys (the
sizes and the number of snapshots, read from the server) and asks you to type
the name (the project name for several); -y does not answer it. Scripts pass
--confirm-data-loss once they have decided. --dry-run shows the same summary
and deletes nothing.`
		cmd.Example = "jailops " + path + " delete NAME\njailops " + path + " delete --dry-run NAME\njailops " + path + " delete --confirm-data-loss NAME1 NAME2"
		cmd.Flags().BoolVar(&confirmLoss, "confirm-data-loss", false, "confirm that the data of the "+d.plural+" is destroyed, without typing the name")
	}
	var before func(context.Context, string) error
	if d.beforeDelete != nil {
		before = d.beforeDelete(cmd)
	}
	var resolve func(context.Context, []string) ([]string, bool, error)
	if d.targets != nil {
		resolve = d.targets(cmd)
		cmd.Args = cobra.ArbitraryArgs
		if d.loss != nil {
			cmd.Long += "\nWith -l or --all the " + d.plural + " are selected by label instead of named; you type the project name to confirm (or pass --confirm-data-loss)."
		} else {
			cmd.Long += "\nWith -l or --all the " + d.plural + " are selected by label instead of named; that is a batch, and you type the project name to confirm it (or pass -y)."
		}
		cmd.Example += "\njailops " + path + " delete -l env=test"
	}
	cmd.RunE = func(cmd *cobra.Command, args []string) error {
		ctx := cmd.Context()
		names, bulk := args, false
		if resolve != nil {
			var err error
			if names, bulk, err = resolve(ctx, args); err != nil {
				return err
			}
			if bulk && len(names) == 0 {
				fprintf(a.env.Stderr, "No %s match.\n", d.plural)
				return nil
			}
		}
		what := d.plural
		if len(names) == 1 {
			what = d.noun
		}
		// What would go, read before anything changes: a missing object is an error, also in a dry run.
		var summary []string
		if d.loss != nil || a.dryRun {
			c, err := a.connect(ctx)
			if err != nil {
				return err
			}
			for _, name := range names {
				if d.loss != nil {
					line, err := d.loss(cmd, ctx, c, name)
					if err != nil {
						return err
					}
					summary = append(summary, line)
				} else if d.get != nil {
					if _, _, err := d.get(ctx, c, name); err != nil {
						return err
					}
				}
			}
		}
		if a.dryRun && d.loss != nil {
			if a.format == fmtJSON || a.format == fmtYAML {
				return a.emit(map[string]any{"dry_run": true, "action": "delete " + what, "destroys": summary}, nil, nil, nil)
			}
			for _, l := range summary {
				fprintf(a.env.Stdout, "dry-run: would delete %s %s\n", d.noun, l)
			}
			return nil
		}
		project := ""
		if a.conn != nil {
			project = a.conn.CurrentProject()
		}
		switch {
		case a.dryRun:
		case d.loss != nil:
			typed := names[0]
			if bulk || len(names) > 1 {
				typed = project
			}
			warn := fmt.Sprintf("This deletes %d %s of project %q and destroys its data; it cannot be undone:\n  %s", len(names), what, project, strings.Join(summary, "\n  "))
			if err := a.confirmTyped(warn, typed, confirmLoss, "--confirm-data-loss"); err != nil {
				return err
			}
		case bulk:
			warn := fmt.Sprintf("This deletes %d %s of project %q: %s. It cannot be undone.", len(names), what, project, strings.Join(names, ", "))
			if err := a.confirmTyped(warn, project, a.yes, "-y"); err != nil {
				return err
			}
		}
		for _, name := range names {
			if before != nil {
				if err := before(ctx, name); err != nil {
					return err
				}
			}
			if ok, err := a.dry(verb+" "+d.noun+" "+name, nil); ok || err != nil {
				if err != nil {
					return err
				}
				continue
			}
			if !bulk && d.loss == nil {
				if err := a.confirm(fmt.Sprintf("%s %s %q?", Verb, d.noun, name)); err != nil {
					return err
				}
			}
			c, err := a.connect(ctx)
			if err != nil {
				return err
			}
			h, err := d.del(ctx, c, name)
			if err != nil {
				return err
			}
			if err := a.finishOp(ctx, h, d.noun, name, past, nil); err != nil {
				return err
			}
		}
		return nil
	}
	parent.AddCommand(cmd)
}

// edit ---------------------------------------------------------------------

// addEdit adds "edit": an editor session on the YAML document, written back
// with the ETag read at the start so a concurrent change is detected.
func addEdit[T any](a *app, parent *cobra.Command, d *kindDesc[T]) {
	var file string
	cmd := &cobra.Command{
		Use:   "edit NAME",
		Short: "Edit " + article(d.noun) + " " + d.noun + " in your editor",
		Long: `Open the specification of ` + article(d.noun) + ` ` + d.noun + ` as YAML in $JAILOPS_EDITOR, $VISUAL or $EDITOR
(default vi), and send it back when the editor exits. The update carries the
ETag of the version you started from: if somebody else changed the object in
the meantime the server answers "conflict" and nothing is overwritten; your
text stays in a temporary file whose path is printed.

Saving without a change, or an empty file, cancels. Only the specification and
the labels can be changed; server-owned fields are not shown. With -f the
document is read from a file instead of an editor, which is how scripts replace
` + article(d.noun) + ` ` + d.noun + `. With --dry-run the edited document is validated and printed,
not sent.`,
		Example:           "EDITOR=nano jailops @P@ edit NAME\njailops @P@ edit NAME -f NAME.yaml",
		Args:              cobra.ExactArgs(1),
		ValidArgsFunction: completeKind(a, d),
		RunE: func(cmd *cobra.Command, args []string) error {
			return editObject(a, cmd.Context(), d, args[0], file, strings.TrimPrefix(cmd.Parent().CommandPath(), "jailops "))
		},
	}
	cmd.Flags().StringVarP(&file, "file", "f", "", "take the new document from this file instead of an editor")
	parent.AddCommand(cmd)
}

func (a *app) editorArgv() []string {
	for _, k := range []string{"JAILOPS_EDITOR", "VISUAL", "EDITOR"} {
		if v := strings.TrimSpace(a.env.Getenv(k)); v != "" {
			return strings.Fields(v)
		}
	}
	return []string{"vi"}
}

func editObject[T any](a *app, ctx context.Context, d *kindDesc[T], name, file, path string) error {
	c, err := a.connect(ctx)
	if err != nil {
		return err
	}
	obj, etag, err := d.get(ctx, c, name)
	if err != nil {
		return err
	}
	orig, err := toYAML(document(d.kind, *d.meta(&obj), d.specOf(&obj)))
	if err != nil {
		return err
	}
	var edited []byte
	keep := ""
	if file != "" {
		if edited, err = a.readInput(file); err != nil {
			return err
		}
	} else {
		header := fmt.Sprintf("# Editing %s %q (generation %d). Save and quit to apply.\n# No change or an empty file cancels. Server-owned fields are not shown.\n",
			d.noun, name, d.meta(&obj).Generation)
		f, err := os.CreateTemp("", "jailops-"+d.noun+"-"+name+"-*.yaml")
		if err != nil {
			return err
		}
		keep = f.Name()
		_, werr := f.WriteString(header + string(orig))
		if cerr := f.Close(); werr == nil {
			werr = cerr
		}
		if werr != nil {
			return werr
		}
		argv := a.editorArgv()
		ec := exec.CommandContext(ctx, argv[0], append(argv[1:], keep)...)
		ec.Stdin, ec.Stdout, ec.Stderr = a.env.Stdin, a.env.Stdout, a.env.Stderr
		if err := ec.Run(); err != nil {
			return &hintError{err: fmt.Errorf("editor %q failed: %w", argv[0], err), hint: "your text is in " + keep}
		}
		if edited, err = os.ReadFile(keep); err != nil {
			return err
		}
	}
	strip := func(b []byte) string {
		var out []string
		for _, l := range strings.Split(string(b), "\n") {
			if !strings.HasPrefix(l, "#") {
				out = append(out, l)
			}
		}
		return strings.TrimSpace(strings.Join(out, "\n"))
	}
	cleanup := func() {
		if keep != "" {
			_ = os.Remove(keep)
		}
	}
	if strip(edited) == "" {
		cleanup()
		fprintln(a.env.Stderr, "Edit cancelled: the file is empty.")
		return nil
	}
	if strip(edited) == strip(orig) {
		cleanup()
		a.say("%s/%s unchanged\n", d.noun, name)
		return nil
	}
	fail := func(err error) error {
		if keep == "" {
			return err
		}
		return &hintError{err: err, hint: fmt.Sprintf("your edit is saved in %s; fix it and apply with: jailops %s edit %s -f %s", keep, path, name, keep)}
	}
	docs, err := readDocs(edited)
	if err != nil {
		return fail(err)
	}
	if len(docs) != 1 {
		return fail(usagef("edit takes exactly one document, found %d", len(docs)))
	}
	// a document that names itself may carry a new name: that is a rename (a bare spec keeps the name)
	nu, err := d.parse(api.ObjectMeta{}, docs[0], "")
	if err != nil {
		nu, err = d.parse(api.ObjectMeta{}, docs[0], name)
	}
	if err != nil {
		return fail(err)
	}
	renamed := false
	if to := d.meta(&nu).Name; to != name {
		renamed = true
		if d.rename == nil {
			return fail(usagef("the name of %s %s cannot change", article(d.noun)+" "+d.noun, name))
		}
		// the rename shows what it changes and asks; the rest of the edit goes to the new name
		if err := a.runRename(ctx, d.noun, name, to, etag, d.rename); err != nil {
			return fail(err)
		}
		if !a.dryRun {
			if obj, etag, err = d.get(ctx, c, to); err != nil {
				return fail(err)
			}
			name = to
		}
		d.meta(&nu).Name = name
	}
	next := obj
	d.setSpec(&next, nu)
	if renamed && sameDocument(d, obj, next) {
		cleanup()
		if !a.dryRun {
			a.say("%s/%s unchanged apart from its name\n", d.noun, name)
		}
		return nil
	}
	if ok, err := a.dry("update "+d.noun+" "+name, document(d.kind, *d.meta(&next), d.specOf(&next))); ok || err != nil {
		cleanup()
		return err
	}
	out, err := d.update(ctx, c, name, next, etag)
	if err != nil {
		var ae *api.Error
		if errors.As(err, &ae) && ae.Code == api.CodeConflict && keep != "" {
			return ae.WithHint(fmt.Sprintf("someone changed the %s while you edited; your text is saved in %s, run edit again and re-apply it", d.noun, keep))
		}
		return fail(err)
	}
	cleanup()
	if err := a.finishOp(ctx, nil, d.noun, name, "updated", out); err != nil {
		return err
	}
	if d.updated != nil {
		d.updated(a, out)
	}
	return nil
}

// sameDocument reports whether two versions of an object have the same specification and labels.
func sameDocument[T any](d *kindDesc[T], a, b T) bool {
	x, err1 := toYAML(document(d.kind, *d.meta(&a), d.specOf(&a)))
	y, err2 := toYAML(document(d.kind, *d.meta(&b), d.specOf(&b)))
	return err1 == nil && err2 == nil && string(x) == string(y)
}

// crudCommands adds list, show, create, edit and delete.
func crudCommands[T any](a *app, parent *cobra.Command, d *kindDesc[T], createLong, createExample string, flagBuild func(*cobra.Command) func(string) (T, error)) {
	addList(a, parent, d, "")
	addShow(a, parent, d)
	addCreate(a, parent, d, createLong, createExample, flagBuild)
	addEdit(a, parent, d)
	if flagBuild != nil && !d.noSet {
		addSet(a, parent, d, flagBuild)
	}
	addDelete(a, parent, d)
	if d.rename != nil {
		addRename(a, parent, d, d.renameLong)
	}
}
