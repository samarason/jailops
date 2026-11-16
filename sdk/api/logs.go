package api

import (
	"encoding/json"
	"net"
	"net/url"
	"path"
	"slices"
	"sort"
	"strconv"
	"strings"
	"time"
)

// Unified logs (extension logs_unified): GET /api/v1/logs reads the end of
// one log file (default messages) of every selected jail, through the same
// per-jail read as GET /api/v1/jails/{name}/logs/{file}, and merges the
// lines into one stream ordered by their timestamps. ?project= selects one
// project; without it every project the caller may use is read.

// Limits of a unified read.
const (
	// MaxLogSources bounds the files one unified read takes.
	MaxLogSources = 50
	// MaxLogMergedLines bounds the lines of one unified reply: the newest are kept.
	MaxLogMergedLines = 2000
	// DefaultLogFile is the file a unified read and the forwarder take of every jail.
	DefaultLogFile = "messages"
	// MaxLogCursor bounds the cursor parameter.
	MaxLogCursor = 32 << 10
)

// LogsQuery is the query string of GET /api/v1/logs.
type LogsQuery struct {
	// Jails narrows the read to these jails (?jail=, repeated).
	Jails []string `json:"jails,omitempty"`
	// Labels keeps the jails that carry every one of these labels (?label=k=v, repeated).
	Labels map[string]string `json:"labels,omitempty"`
	// App keeps the jails installed from this catalog app (the jailops.app label).
	App string `json:"app,omitempty"`
	// AppLogs adds the log files an installed app declares below /var/log.
	AppLogs bool `json:"app_logs,omitempty"`
	// File is the file read of every jail (default messages).
	File string `json:"file,omitempty"`
	// Tail, Since and Grep apply to every source before the merge.
	Tail  int    `json:"tail,omitempty"`
	Since string `json:"since,omitempty"`
	Grep  string `json:"grep,omitempty"`
	// Cursor continues a previous read: the next map of its reply, by source key.
	Cursor map[string]int64 `json:"cursor,omitempty"`
}

// LogEntry is one line of a unified read.
type LogEntry struct {
	// Time is the timestamp the line starts with; absent when it has none.
	Time    *time.Time `json:"time,omitempty"`
	Project string     `json:"project"`
	Jail    string     `json:"jail"`
	App     string     `json:"app,omitempty"`
	File    string     `json:"file"`
	Line    string     `json:"line"`
}

// LogSource is one file a unified read took.
type LogSource struct {
	// Key is project/jail/file, the key of the next and cursor maps.
	Key        string `json:"key"`
	Project    string `json:"project"`
	Jail       string `json:"jail"`
	App        string `json:"app,omitempty"`
	File       string `json:"file"`
	NextOffset int64  `json:"next_offset"`
	Rotated    bool   `json:"rotated,omitempty"`
	Truncated  bool   `json:"truncated,omitempty"`
	// Error says why the source gave no lines (a jail that is not mounted: busy; a missing file: not_found).
	Error *Error `json:"error,omitempty"`
}

// LogsRead is the reply of GET /api/v1/logs.
type LogsRead struct {
	Lines   []LogEntry  `json:"lines"`
	Sources []LogSource `json:"sources"`
	// Next maps every source key to the offset to continue from: send it back as cursor to follow.
	Next map[string]int64 `json:"next"`
	// Truncated is true when a limit (MaxLogSources, MaxLogMergedLines, a source's tail) left lines out.
	Truncated bool `json:"truncated,omitempty"`
}

// LogSourceKey is the key of a source in the next and cursor maps.
func LogSourceKey(project, jail, file string) string { return project + "/" + jail + "/" + file }

// Normalize fills the defaults and checks the limits.
func (q LogsQuery) Normalize() (LogsQuery, error) {
	if q.File == "" {
		q.File = DefaultLogFile
	}
	if err := ValidLogFileName(q.File); err != nil {
		return q, err
	}
	if _, compressed := LogFileKind(q.File); compressed {
		return q, Errorf(CodeInvalid, "%s is not readable (compressed)", q.File)
	}
	if len(q.Jails) > MaxLogSources {
		return q, Errorf(CodeInvalid, "at most %d jails", MaxLogSources)
	}
	for _, j := range q.Jails {
		if !IsName(j, MaxName) {
			return q, Errorf(CodeInvalid, "jail %q is not a jail name", j)
		}
	}
	if q.App != "" && !IsName(q.App, MaxName) {
		return q, Errorf(CodeInvalid, "app %q is not an app name", q.App)
	}
	for k := range q.Labels {
		if k == "" || len(k) > 253 {
			return q, Errorf(CodeInvalid, "invalid label selector %q", k)
		}
	}
	for k, v := range q.Cursor {
		if v < 0 || strings.Count(k, "/") < 2 {
			return q, Errorf(CodeInvalid, "cursor: %q is not a source key with an offset", k)
		}
	}
	lq, err := JailLogQuery{Tail: q.Tail, Since: q.Since, Grep: q.Grep}.Normalize()
	if err != nil {
		return q, err
	}
	q.Tail = lq.Tail
	return q, nil
}

// ParseLogsQuery reads a LogsQuery from a query string.
func ParseLogsQuery(v url.Values) (LogsQuery, error) {
	q := LogsQuery{Jails: v["jail"], App: v.Get("app"), File: v.Get("file"), Since: v.Get("since"), Grep: v.Get("grep")}
	for _, l := range v["label"] {
		k, val, ok := strings.Cut(l, "=")
		if !ok || k == "" {
			return q, Errorf(CodeInvalid, "invalid label selector %q (use key=value)", l)
		}
		if q.Labels == nil {
			q.Labels = map[string]string{}
		}
		q.Labels[k] = val
	}
	switch v.Get("app_logs") {
	case "", "false", "0":
	case "true", "1":
		q.AppLogs = true
	default:
		return q, Errorf(CodeInvalid, "app_logs is true or false")
	}
	if s := v.Get("tail"); s != "" {
		n, err := strconv.Atoi(s)
		if err != nil || n < 1 {
			return q, Errorf(CodeInvalid, "tail must be a number of lines between 1 and %d", MaxLogTail)
		}
		q.Tail = n
	}
	if s := v.Get("cursor"); s != "" {
		if len(s) > MaxLogCursor {
			return q, Errorf(CodeInvalid, "cursor is at most %d bytes", MaxLogCursor)
		}
		if err := json.Unmarshal([]byte(s), &q.Cursor); err != nil {
			return q, Errorf(CodeInvalid, "cursor is the next map of a previous reply, as JSON")
		}
	}
	return q.Normalize()
}

// Values is the query string of q; defaults are left out.
func (q LogsQuery) Values() url.Values {
	v := url.Values{}
	for _, j := range q.Jails {
		v.Add("jail", j)
	}
	keys := make([]string, 0, len(q.Labels))
	for k := range q.Labels {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		v.Add("label", k+"="+q.Labels[k])
	}
	if q.App != "" {
		v.Set("app", q.App)
	}
	if q.AppLogs {
		v.Set("app_logs", "true")
	}
	if q.File != "" && q.File != DefaultLogFile {
		v.Set("file", q.File)
	}
	if q.Tail > 0 && q.Tail != DefaultLogTail {
		v.Set("tail", strconv.Itoa(q.Tail))
	}
	if q.Since != "" {
		v.Set("since", q.Since)
	}
	if q.Grep != "" {
		v.Set("grep", q.Grep)
	}
	if len(q.Cursor) > 0 {
		b, _ := json.Marshal(q.Cursor) // map keys are sorted
		v.Set("cursor", string(b))
	}
	return v
}

// LogSourceLines are the lines read from one source, in file order, for MergeLogs.
type LogSourceLines struct {
	Project, Jail, App, File string
	Lines                    []string
}

// MergeLogs merges the lines of several sources into one stream ordered by
// timestamp. A line without a timestamp of its own takes the one of the line
// before it in its source (the lines before the first timestamp take that
// first one; a source without any sorts first), so the lines of one source
// always keep their order. Equal times keep the order of the sources. Only
// the newest limit lines are kept; truncated says that some were left out.
func MergeLogs(sources []LogSourceLines, limit int, now time.Time) (out []LogEntry, truncated bool) {
	type line struct {
		own *time.Time
		key time.Time
	}
	keyed := make([][]line, len(sources))
	total := 0
	for i, s := range sources {
		ls := make([]line, len(s.Lines))
		var last time.Time
		first := -1
		for k, text := range s.Lines {
			if t, ok := LogLineTime(text, now); ok {
				t = t.UTC()
				ls[k].own = &t
				last = t
				if first < 0 {
					first = k
				}
			}
			ls[k].key = last
		}
		for k := 0; k < first; k++ {
			ls[k].key = *ls[first].own
		}
		keyed[i] = ls
		total += len(ls)
	}
	out = make([]LogEntry, 0, min(total, max(limit, 0)))
	pos := make([]int, len(sources))
	skip := total - limit // the oldest lines that do not fit
	if limit <= 0 {
		skip = 0
	}
	for n := 0; n < total; n++ {
		best := -1
		for i := range sources {
			if pos[i] < len(keyed[i]) && (best < 0 || keyed[i][pos[i]].key.Before(keyed[best][pos[best]].key)) {
				best = i
			}
		}
		l := keyed[best][pos[best]]
		s := sources[best]
		pos[best]++
		if n < skip {
			truncated = true
			continue
		}
		out = append(out, LogEntry{Time: l.own, Project: s.Project, Jail: s.Jail, App: s.App, File: s.File, Line: s.Lines[pos[best]-1]})
	}
	return out, truncated
}

// Log forwarding (extension log_forward): jailopsd sends the log lines of the
// jails, and optionally its audit log, to syslog servers and webhooks. The
// sinks come from logging.forward of jailopsd.yaml, unless an administrator
// stored a LogForward object through PUT /api/v1/logs/forward, which then
// replaces the file's list until it is deleted.

// LogSinkType is the protocol of a sink.
type LogSinkType string

// Sink types.
const (
	// LogSinkSyslog sends RFC 5424 messages over udp, tcp or tls (octet-counted framing on a stream).
	LogSinkSyslog LogSinkType = "syslog"
	// LogSinkWebhook POSTs batches of JSON lines to an https URL.
	LogSinkWebhook LogSinkType = "webhook"
)

// Limits and defaults of forwarding.
const (
	MaxLogSinks          = 16
	DefaultLogQueue      = 10000
	MinLogQueue          = 100
	MaxLogQueue          = 1000000
	MaxLogForwardLine    = 8 << 10 // bytes of one line; the rest is cut
	DefaultSyslogPort    = 514
	DefaultSyslogTLSPort = 6514
	// LogSourceAudit is the source key of the daemon's audit log.
	LogSourceAudit = "audit"
)

// LogForwardSpec is the list of sinks.
type LogForwardSpec struct {
	Sinks []LogSink `json:"sinks" yaml:"sinks"`
}

// LogSink is one destination.
type LogSink struct {
	// Name is a short slug (^[a-z][a-z0-9-]{0,31}$), unique in the list.
	Name string      `json:"name" yaml:"name"`
	Type LogSinkType `json:"type" yaml:"type"`
	// To is where lines go: udp://, tcp:// or tls://HOST[:PORT] for syslog
	// (default port 514, 6514 for tls), an https:// URL for a webhook.
	To string `json:"to" yaml:"to"`
	// Facility is local0 to local7 (syslog; default local0).
	Facility string `json:"facility,omitempty" yaml:"facility"`
	// CAFile is a PEM file of the certificate authorities to verify the
	// receiver with (tls and webhook); empty uses the host's roots.
	// Verification cannot be switched off.
	CAFile string `json:"ca_file,omitempty" yaml:"ca_file"`
	// TokenFile holds the bearer token of a webhook (first line). It is a
	// root-owned file the daemon can read (0600 or 0640 root:jailops); the
	// token itself never appears in the configuration or the API.
	TokenFile string `json:"token_file,omitempty" yaml:"token_file"`
	// Queue bounds the lines held for the sink (default 10000); when it is
	// full the oldest are dropped and counted.
	Queue   int           `json:"queue,omitempty" yaml:"queue"`
	Sources LogSinkSource `json:"sources,omitzero" yaml:"sources"`
}

// LogSinkSource selects what a sink receives. The zero value is the file
// messages of every jail plus the logs of installed apps.
type LogSinkSource struct {
	// Projects, Jails and Labels narrow the jails (all of them must match when set).
	Projects []string          `json:"projects,omitempty" yaml:"projects"`
	Jails    []string          `json:"jails,omitempty" yaml:"jails"`
	Labels   map[string]string `json:"labels,omitempty" yaml:"labels"`
	// ExcludeJails and ExcludeLabels drop jails (a jail with any one of these labels).
	ExcludeJails  []string          `json:"exclude_jails,omitempty" yaml:"exclude_jails"`
	ExcludeLabels map[string]string `json:"exclude_labels,omitempty" yaml:"exclude_labels"`
	// Files replaces messages as the files read of every jail (names below /var/log).
	Files []string `json:"files,omitempty" yaml:"files"`
	// NoAppLogs leaves out the logs installed apps declare.
	NoAppLogs bool `json:"no_app_logs,omitempty" yaml:"no_app_logs"`
	// NoJails sends no jail logs (with Audit: the audit log only).
	NoJails bool `json:"no_jails,omitempty" yaml:"no_jails"`
	// Audit adds the daemon's audit log as the source audit.
	Audit bool `json:"audit,omitempty" yaml:"audit"`
}

// LogForward is the reply of GET and PUT /api/v1/logs/forward.
type LogForward struct {
	Kind   Kind             `json:"kind"`
	Spec   LogForwardSpec   `json:"spec"`
	Status LogForwardStatus `json:"status"`
}

// LogForwardStatus is what the forwarder reports.
type LogForwardStatus struct {
	// Origin is "config" (logging.forward of jailopsd.yaml) or "api" (a stored object replaces the file's list).
	Origin string `json:"origin"`
	// Generation is the generation of the stored object (0 for the file); send it as If-Match.
	Generation int64           `json:"generation"`
	UpdatedAt  *time.Time      `json:"updated_at,omitempty"`
	Sinks      []LogSinkStatus `json:"sinks"`
}

// Origins of the sink list.
const (
	LogForwardFromConfig = "config"
	LogForwardFromAPI    = "api"
)

// LogSinkStatus is the state of one sink.
type LogSinkStatus struct {
	Name string      `json:"name"`
	Type LogSinkType `json:"type"`
	To   string      `json:"to"`
	// Sources is the number of files (and the audit log) read for the sink.
	Sources int   `json:"sources"`
	Sent    int64 `json:"sent"`
	Queued  int   `json:"queued"`
	Dropped int64 `json:"dropped"`
	// SkippedBytes counts what was written faster than it could be read (more than 1 MiB of a file between two reads) and never read.
	SkippedBytes int64      `json:"skipped_bytes,omitempty"`
	LastSuccess  *time.Time `json:"last_success,omitempty"`
	// FailingSince is when the current run of failures began; absent while the sink works.
	FailingSince *time.Time `json:"failing_since,omitempty"`
	LastError    string     `json:"last_error,omitempty"`
	// Warning is set once for a plain udp or tcp sink to an address that is not a loopback one.
	Warning string `json:"warning,omitempty"`
}

// LogForwardTest is the body of POST /api/v1/logs/forward/test.
type LogForwardTest struct {
	Sink string `json:"sink"`
}

// LogForwardTestResult is its reply: one tagged line was sent, or why not.
type LogForwardTestResult struct {
	Sink  string `json:"sink"`
	OK    bool   `json:"ok"`
	Line  string `json:"line"`
	Error string `json:"error,omitempty"`
	// Millis is how long the send took.
	Millis int64 `json:"millis"`
}

var (
	facilities = []string{"local0", "local1", "local2", "local3", "local4", "local5", "local6", "local7"}
)

// SyslogFacility returns the facility number of local0 to local7 ("" is local0).
func SyslogFacility(name string) (int, bool) {
	if name == "" {
		return 16, true
	}
	i := slices.Index(facilities, name)
	return 16 + i, i >= 0
}

// SinkTarget splits To into the transport (udp, tcp, tls or https) and the
// host:port to connect to, with the default port filled in.
func (s LogSink) SinkTarget() (transport, hostport string, err error) {
	u, err := url.Parse(s.To)
	if err != nil || u.Host == "" || u.User != nil || u.Opaque != "" {
		return "", "", Errorf(CodeInvalid, "sink %q: to %q is not a URL such as tls://logs.example.com:6514", s.Name, s.To)
	}
	host, port := u.Hostname(), u.Port()
	if host == "" {
		return "", "", Errorf(CodeInvalid, "sink %q: to %q names no host", s.Name, s.To)
	}
	switch s.Type {
	case LogSinkSyslog:
		switch u.Scheme {
		case "udp", "tcp":
			port = cmpOr(port, strconv.Itoa(DefaultSyslogPort))
		case "tls":
			port = cmpOr(port, strconv.Itoa(DefaultSyslogTLSPort))
		default:
			return "", "", Errorf(CodeInvalid, "sink %q: a syslog sink is udp://, tcp:// or tls://HOST[:PORT], not %q", s.Name, u.Scheme+"://")
		}
		if (u.Path != "" && u.Path != "/") || u.RawQuery != "" || u.Fragment != "" {
			return "", "", Errorf(CodeInvalid, "sink %q: a syslog address has no path or query", s.Name)
		}
	case LogSinkWebhook:
		if u.Scheme != "https" {
			return "", "", Errorf(CodeInvalid, "sink %q: a webhook is an https:// URL", s.Name).WithHint("plain http would send the logs and the token in the clear")
		}
		port = cmpOr(port, "443")
	default:
		return "", "", Errorf(CodeInvalid, "sink %q: type is syslog or webhook", s.Name)
	}
	if n, err := strconv.Atoi(port); err != nil || n < 1 || n > 65535 {
		return "", "", Errorf(CodeInvalid, "sink %q: port %q is not a port", s.Name, port)
	}
	return u.Scheme, net.JoinHostPort(host, port), nil
}

func cmpOr(a, b string) string {
	if a != "" {
		return a
	}
	return b
}

// Plaintext reports whether the sink sends in the clear to an address that
// is not a loopback one (a host name counts as remote).
func (s LogSink) Plaintext() bool {
	tr, hp, err := s.SinkTarget()
	if err != nil || (tr != "udp" && tr != "tcp") {
		return false
	}
	h, _, _ := net.SplitHostPort(hp)
	if h == "localhost" {
		return false
	}
	ip := net.ParseIP(h)
	return ip == nil || !ip.IsLoopback()
}

func cleanAbsPath(p string) bool {
	return strings.HasPrefix(p, "/") && path.Clean(p) == p && len(p) <= 1024 && !strings.ContainsAny(p, "\x00\n")
}

// Validate checks the sink list lexically. Files named by the list are
// checked by the daemon, which can see them.
func (s LogForwardSpec) Validate() error {
	if len(s.Sinks) > MaxLogSinks {
		return Errorf(CodeInvalid, "at most %d sinks", MaxLogSinks)
	}
	seen := map[string]bool{}
	for _, k := range s.Sinks {
		if !IsName(k.Name, 32) {
			return Errorf(CodeInvalid, "sink name %q must match "+NamePattern+" and have at most 32 characters", k.Name)
		}
		if seen[k.Name] {
			return Errorf(CodeInvalid, "sink %q is listed twice", k.Name)
		}
		seen[k.Name] = true
		tr, _, err := k.SinkTarget()
		if err != nil {
			return err
		}
		if k.Type == LogSinkSyslog {
			if _, ok := SyslogFacility(k.Facility); !ok {
				return Errorf(CodeInvalid, "sink %q: facility is local0 to local7, not %q", k.Name, k.Facility)
			}
			if k.TokenFile != "" {
				return Errorf(CodeInvalid, "sink %q: a token file is for webhooks", k.Name)
			}
		} else if k.Facility != "" {
			return Errorf(CodeInvalid, "sink %q: a facility is for syslog sinks", k.Name)
		}
		if k.CAFile != "" && tr != "tls" && tr != "https" {
			return Errorf(CodeInvalid, "sink %q: a CA file is for tls and webhook sinks", k.Name)
		}
		for what, p := range map[string]string{"ca_file": k.CAFile, "token_file": k.TokenFile} {
			if p != "" && !cleanAbsPath(p) {
				return Errorf(CodeInvalid, "sink %q: %s %q must be a clean absolute path", k.Name, what, p)
			}
		}
		if k.Queue != 0 && (k.Queue < MinLogQueue || k.Queue > MaxLogQueue) {
			return Errorf(CodeInvalid, "sink %q: queue is between %d and %d lines", k.Name, MinLogQueue, MaxLogQueue)
		}
		src := k.Sources
		for _, l := range [][]string{src.Projects, src.Jails, src.ExcludeJails} {
			for _, n := range l {
				if !IsName(n, MaxName) {
					return Errorf(CodeInvalid, "sink %q: %q is not a project or jail name", k.Name, n)
				}
			}
		}
		for _, m := range []map[string]string{src.Labels, src.ExcludeLabels} {
			for lk := range m {
				if lk == "" || len(lk) > 253 || strings.ContainsAny(lk, "=\x00") {
					return Errorf(CodeInvalid, "sink %q: invalid label key %q", k.Name, lk)
				}
			}
		}
		if len(src.Files) > 8 {
			return Errorf(CodeInvalid, "sink %q: at most 8 files per jail", k.Name)
		}
		for _, f := range src.Files {
			if err := ValidLogFileName(f); err != nil {
				return err
			}
			if kind, _ := LogFileKind(f); kind != JailLogActive {
				return Errorf(CodeInvalid, "sink %q: %s is a rotated copy; name the file being written", k.Name, f)
			}
		}
		if src.NoJails && !src.Audit {
			return Errorf(CodeInvalid, "sink %q: with no_jails it needs audit, or it receives nothing", k.Name)
		}
	}
	return nil
}
