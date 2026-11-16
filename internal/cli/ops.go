package cli

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"sync"

	"github.com/spf13/cobra"

	"jailops.net/jailops/sdk"
	"jailops.net/jailops/sdk/api"
)

// idOp follows an operation known only by its id.
type idOp struct {
	c  *sdk.Client
	mu sync.Mutex
	op api.Operation
}

func (o *idOp) Info() api.Operation { o.mu.Lock(); defer o.mu.Unlock(); return o.op }
func (o *idOp) Refresh(ctx context.Context) error {
	op, err := o.c.Operations().Get(ctx, o.Info().ID)
	if err == nil {
		o.mu.Lock()
		o.op = op
		o.mu.Unlock()
	}
	return err
}
func (o *idOp) WaitAny(ctx context.Context) (any, error) {
	op, err := o.c.Operations().Wait(ctx, o.Info().ID)
	o.mu.Lock()
	o.op = op
	o.mu.Unlock()
	return nil, err
}

func (a *app) completeOps() func(*cobra.Command, []string, string) ([]string, cobra.ShellCompDirective) {
	return a.completeNames(func(ctx context.Context, c *sdk.Client) ([]string, error) {
		items, err := collect(c.Operations().List(ctx))
		var n []string
		for _, o := range items {
			n = append(n, o.ID)
		}
		return n, err
	})
}

func (a *app) opCmd() *cobra.Command {
	oc := group("op", "Inspect, wait for and cancel operations",
		`Changes that take time (creating or deleting a jail, building an image,
restoring a backup) run as operations on the server. Commands wait for them by
default; with --no-wait they print the operation id, which these commands then
follow.`,
		"jailops op list\njailops op show 3f1c...\njailops op wait 3f1c...\njailops op cancel 3f1c...", "operation", "operations")
	var active bool
	list := &cobra.Command{
		Use:     "list",
		Aliases: []string{"ls"},
		Short:   "List operations",
		Long:    "List the operations the server remembers; --active keeps only the ones still running.\nWithout a project every operation you may see is listed, host-level ones included; --project narrows the list to one project.",
		Example: "jailops op list\njailops op list --active\njailops op list --project web",
		Args:    cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			c, err := a.connect(cmd.Context())
			if err != nil {
				return err
			}
			all, err := collect(c.Operations().List(cmd.Context()))
			if err != nil {
				return err
			}
			items := all[:0]
			for _, o := range all {
				if !active || !o.Status.Final() {
					items = append(items, o)
				}
			}
			return a.emit(nonNil(items), stateStyle(1), func() ([]string, [][]string) {
				var rows [][]string
				for _, o := range items {
					prog := "-"
					if o.Progress > 0 {
						prog = fmt.Sprintf("%d%%", o.Progress)
					}
					rows = append(rows, []string{o.ID, string(o.Status), prog, age(a.env.Now(), o.CreatedAt), o.Description})
				}
				return []string{"ID", "STATUS", "PROGRESS", "AGE", "DESCRIPTION"}, rows
			}, func() []string {
				var n []string
				for _, o := range items {
					n = append(n, o.ID)
				}
				return n
			})
		},
	}
	list.Flags().BoolVar(&active, "active", false, "only operations that have not finished")
	show := &cobra.Command{
		Use:               "show ID",
		Short:             "Show one operation",
		Long:              "Show one operation: its status, the objects it affects, its result or its error.",
		Example:           "jailops op show 3f1c8a52-...",
		Args:              cobra.ExactArgs(1),
		ValidArgsFunction: a.completeOps(),
		RunE: func(cmd *cobra.Command, args []string) error {
			c, err := a.connect(cmd.Context())
			if err != nil {
				return err
			}
			o, err := c.Operations().Get(cmd.Context(), args[0])
			if err != nil {
				return err
			}
			return a.emit(o, nil, nil, func() []string { return []string{o.ID} })
		},
	}
	wait := &cobra.Command{
		Use:   "wait ID",
		Short: "Wait for an operation to finish",
		Long: `Wait for an operation to end, with a progress line on a terminal. The exit status
is that of the operation's error code when it failed, and 1 when it was
cancelled. --timeout bounds the wait; the operation itself keeps running.`,
		Example:           "jailops op wait 3f1c8a52-... --timeout 30m",
		Args:              cobra.ExactArgs(1),
		ValidArgsFunction: a.completeOps(),
		RunE: func(cmd *cobra.Command, args []string) error {
			c, err := a.connect(cmd.Context())
			if err != nil {
				return err
			}
			first, err := c.Operations().Get(cmd.Context(), args[0])
			if err != nil {
				return err
			}
			h := &idOp{c: c, op: first}
			_, op, err := a.await(cmd.Context(), h)
			if err != nil {
				return err
			}
			return a.finishOpRecord(op)
		},
	}
	cancel := &cobra.Command{
		Use:               "cancel ID",
		Short:             "Cancel a running operation",
		Long:              "Ask the server to cancel an operation. Only operations that report may_cancel can be stopped; the server rolls back what it can.",
		Example:           "jailops op cancel 3f1c8a52-...",
		Args:              cobra.ExactArgs(1),
		ValidArgsFunction: a.completeOps(),
		RunE: func(cmd *cobra.Command, args []string) error {
			if ok, err := a.dry("cancel operation "+args[0], nil); ok || err != nil {
				return err
			}
			c, err := a.connect(cmd.Context())
			if err != nil {
				return err
			}
			if err := c.Operations().Cancel(cmd.Context(), args[0]); err != nil {
				return err
			}
			return a.finishOp(cmd.Context(), nil, "operation", args[0], "cancelled", nil)
		},
	}
	oc.AddCommand(list, show, wait, cancel)
	return oc
}

func (a *app) finishOpRecord(op api.Operation) error {
	return a.emit(op, nil, func() ([]string, [][]string) {
		return []string{"ID", "STATUS", "DESCRIPTION"}, [][]string{{op.ID, string(op.Status), op.Description}}
	}, func() []string { return []string{op.ID} })
}

// events ----------------------------------------------------------------------

func (a *app) eventsCmd() *cobra.Command {
	var types []string
	var jail, since string
	var count int
	cmd := &cobra.Command{
		Use:   "events",
		Short: "Stream events from the server",
		Long: `Stream lifecycle, operation and logging events until interrupted. In the default
output each event is one line; with -o json each event is one JSON object per
line, and with -o yaml a stream of documents.

The stream reconnects after a drop and resumes from the last event it saw.
--type, --jail and --project filter (without a project every event you may see
is streamed, host-level ones included); --since-id replays events the server
still retains; --count stops after that many events.`,
		Example: `jailops events
jailops events --type lifecycle,operation --jail web
jailops events --project web
jailops events -o json --count 10 --since-id 0`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			var ts []api.EventType
			for _, t := range types {
				for _, p := range strings.Split(t, ",") {
					switch api.EventType(p) {
					case api.EventLifecycle, api.EventOperation, api.EventLogging:
						ts = append(ts, api.EventType(p))
					case "":
					default:
						return usagef("unknown event type %q (use lifecycle, operation or logging)", p)
					}
				}
			}
			return a.streamEvents(cmd.Context(), ts, jail, since, count)
		},
	}
	cmd.Flags().StringArrayVar(&types, "type", nil, "event types: lifecycle, operation, logging (comma list or repeated)")
	cmd.Flags().StringVar(&jail, "jail", "", "only events about this jail")
	cmd.Flags().StringVar(&since, "since-id", "", "resume after this event id")
	cmd.Flags().IntVar(&count, "count", 0, "stop after this many events")
	enumFlag(cmd, "type", string(api.EventLifecycle), string(api.EventOperation), string(api.EventLogging))
	a.completeFlag(cmd, "jail", listNames(func(ctx context.Context, c *sdk.Client) iterNames {
		return namesOf(c.Jails().List(ctx), func(j api.Jail) string { return j.Metadata.Name })
	}))
	return cmd
}

func eventMentions(ev api.Event, jail string) bool {
	raw := string(ev.Metadata)
	return strings.Contains(raw, "/jails/"+jail+`"`) || strings.Contains(raw, "/jails/"+jail+"/") ||
		strings.Contains(raw, `"jail":"`+jail+`"`)
}

func eventLine(a *app, ev api.Event) string {
	detail := string(ev.Metadata)
	switch ev.Type {
	case api.EventLifecycle:
		var l api.LifecycleEvent
		if json.Unmarshal(ev.Metadata, &l) == nil && l.Action != "" {
			detail = l.Action + " " + l.Source
			if l.Detail != "" {
				detail += ": " + l.Detail
			}
			if l.Requestor != "" {
				detail += " by " + l.Requestor
			}
		}
	case api.EventOperation:
		var o api.Operation
		if json.Unmarshal(ev.Metadata, &o) == nil && o.ID != "" {
			detail = fmt.Sprintf("%s %s %s", o.ID, o.Status, o.Description)
		}
	case api.EventLogging:
		var m map[string]any
		if json.Unmarshal(ev.Metadata, &m) == nil {
			if msg, ok := m["message"].(string); ok {
				detail = msg
			}
		}
	}
	return fmt.Sprintf("%s  %-9s %s", ev.Timestamp.UTC().Format("15:04:05"), ev.Type, detail)
}

func (a *app) streamEvents(ctx context.Context, types []api.EventType, jail, since string, count int) error {
	c, err := a.connect(ctx)
	if err != nil {
		return err
	}
	var opts []sdk.EventOption
	if len(types) > 0 {
		opts = append(opts, sdk.Types(types...))
	}
	if since != "" {
		opts = append(opts, sdk.FromID(since))
	}
	n := 0
	for ev, err := range c.Events(ctx, opts...) {
		if err != nil {
			if errors.Is(err, context.Canceled) || errors.Is(err, sdk.ErrClosed) {
				return nil
			}
			return err
		}
		if jail != "" && !eventMentions(ev, jail) {
			continue
		}
		switch a.format {
		case fmtJSON:
			enc := json.NewEncoder(a.env.Stdout)
			enc.SetEscapeHTML(false)
			if err := enc.Encode(ev); err != nil {
				return err
			}
		case fmtYAML:
			b, err := toYAML(ev)
			if err != nil {
				return err
			}
			fprintf(a.env.Stdout, "---\n%s", b)
		case fmtName:
			name := string(ev.Type)
			var l api.LifecycleEvent
			if json.Unmarshal(ev.Metadata, &l) == nil && l.Source != "" {
				name = l.Source
			}
			fprintln(a.env.Stdout, name)
		default:
			fprintln(a.env.Stdout, eventLine(a, ev))
		}
		n++
		if count > 0 && n >= count {
			return nil
		}
	}
	return nil
}
