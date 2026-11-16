package priv

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"log/syslog"
	"strconv"
	"strings"
	"time"
)

// Auditor writes one structured line per privileged request, as JSON, to an
// io.Writer: stderr, a file or syslog. File contents, rulesets, property
// values and command arguments beyond the program name are never logged.
type Auditor struct {
	l *slog.Logger
}

// NewAuditor logs JSON lines to w.
func NewAuditor(w io.Writer) *Auditor {
	return &Auditor{l: slog.New(slog.NewJSONHandler(w, &slog.HandlerOptions{
		ReplaceAttr: func(groups []string, a slog.Attr) slog.Attr {
			if len(groups) == 0 && a.Key == slog.MessageKey {
				a.Key = "event"
			}
			return a
		},
	}))}
}

// NewSyslogAuditor logs JSON lines to syslog (facility auth, tag tag).
// UNVERIFIED on FreeBSD: the syslog socket path and the tag in the line.
func NewSyslogAuditor(tag string) (*Auditor, error) {
	w, err := syslog.New(syslog.LOG_NOTICE|syslog.LOG_AUTH, tag)
	if err != nil {
		return nil, err
	}
	return NewAuditor(w), nil
}

// discardAuditor drops everything (tests).
func discardAuditor() *Auditor { return NewAuditor(io.Discard) }

// AuditEvent describes one request.
type AuditEvent struct {
	Conn    uint64
	UID     uint32
	PID     int32
	Req     uint64
	Op      string
	Admin   string
	Target  map[string]string
	Outcome string // "start", "ok" or an error code
	Err     string
	Dur     time.Duration
}

// Log writes the event.
func (a *Auditor) Log(ev AuditEvent) {
	if a == nil {
		return
	}
	attrs := []any{
		slog.Uint64("conn", ev.Conn), slog.Uint64("uid", uint64(ev.UID)), slog.Int("pid", int(ev.PID)),
		slog.Uint64("req", ev.Req), slog.String("op", ev.Op), slog.String("outcome", ev.Outcome),
	}
	if ev.Admin != "" {
		attrs = append(attrs, slog.String("admin", ev.Admin))
	}
	if len(ev.Target) > 0 {
		attrs = append(attrs, slog.Any("target", ev.Target))
	}
	if ev.Err != "" {
		attrs = append(attrs, slog.String("error", clip(ev.Err, 300)))
	}
	if ev.Dur > 0 {
		attrs = append(attrs, slog.Int64("dur_ms", ev.Dur.Milliseconds()))
	}
	lvl := slog.LevelInfo
	if ev.Outcome != "ok" && ev.Outcome != "start" {
		lvl = slog.LevelWarn
	}
	a.l.Log(context.Background(), lvl, "priv.request", attrs...)
}

// Note logs a connection level event.
func (a *Auditor) Note(msg string, attrs ...any) {
	if a != nil {
		a.l.Info(msg, attrs...)
	}
}

func clip(s string, n int) string {
	if len(s) > n {
		return s[:n] + "..."
	}
	return s
}

// targetKeys are the argument fields that name what a request acts on.
var targetKeys = []string{"name", "snapshot", "target", "dataset", "anchor", "path", "iface", "jail", "from", "to", "conf", "table", "tag", "src", "dst", "addr", "uplink", "requester_ip"}

// auditTarget extracts the named targets of a request. For commands only the
// program (or the jail command's first word) is recorded.
func auditTarget(op string, raw json.RawMessage) map[string]string {
	var m map[string]json.RawMessage
	if json.Unmarshal(raw, &m) != nil {
		return nil
	}
	out := map[string]string{}
	for _, k := range targetKeys {
		if v, ok := m[k]; ok {
			var s string
			if json.Unmarshal(v, &s) == nil && s != "" {
				out[k] = clip(s, 200)
			}
		}
	}
	if strings.HasPrefix(op, "zfs.") {
		for _, k := range []string{"snapshots", "names"} {
			var l []string
			if json.Unmarshal(m[k], &l) == nil && len(l) > 0 {
				out[k] = clip(strings.Join(l, ","), 300)
			}
		}
	}
	if v, ok := m["argv"]; ok {
		var l []string
		if json.Unmarshal(v, &l) == nil && len(l) > 0 {
			out["cmd"] = clip(l[0], 100)
			if op == OpExecSession {
				// The program and how many arguments it got: a command line may carry a secret, and the log is
				// readable by whoever reads the helper's logs.
				out["argv"] = clip(l[0], 100) + " (" + strconv.Itoa(len(l)-1) + " arguments)"
			}
		}
	}
	if len(out) == 0 {
		return nil
	}
	return out
}
