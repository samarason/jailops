package apps

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"

	"jailops.net/jailops/sdk/api"
)

// Draft is a definition written as a commented file for a person to
// complete: what 'jailops app new' and 'jailops app export' produce. Every
// top-level key is written, with a short comment that says what it does and
// what usually goes wrong; Todo adds a TODO line above a key. The file
// parses and validates as it is (Check then reports the TODO lines).
type Draft struct {
	App api.App
	// Todo holds, per top-level key, what is left to do there.
	Todo map[string]string
	// Header lines are written as comments below the standard header.
	Header []string
}

// sectionComments are written above the keys they name.
var sectionComments = map[string][]string{
	"version":     {"Format version of the definition; 1."},
	"name":        {"The app name: a jail name (^[a-z][a-z0-9-]{0,62}$), equal to the file name without .yaml."},
	"title":       {"One line, at most 80 characters."},
	"summary":     {"One line, at most 140 characters: what it is and what it is for."},
	"description": {"Plain text paragraphs, no markup, at most 2000 characters."},
	"category":    {"One of " + joinCategories() + "."},
	"homepage":    {"The software's https homepage."},
	"license":     {"The software's license, as its SPDX name (BSD-2-Clause, MIT, Apache-2.0, ...)."},
	"icon":        {"A .svg or .png next to this file, at most 64 KB; leave it out for none."},
	"image":       {"FreeBSD only, 15.1 or later."},
	"packages": {
		"Installed from the host with pkg -r into the jail root: repo ports (the FreeBSD",
		"repository, the default) or jailops (pkg.jailops.net). version is what you tested",
		"against, not a pin. The installer runs ldconfig in the jail afterwards itself.",
	},
	"services": {
		"rc.d scripts, in start order. The installer writes <name>_enable=\"YES\" itself; rc holds",
		"the other rc.conf knobs. start: false enables a service without starting it. A start",
		"runs through a wrapper that detaches the output, so an rc script that leaves a",
		"daemon(8) supervisor behind does not hang the installation.",
	},
	"ports": {
		"What the services listen on, declared honestly (proto tcp or udp; say so when a port",
		"listens on localhost only). expose: true asks for forwarding, which is not done yet.",
	},
	"data": {
		"Every directory that holds state. Each becomes a volume of its own (snapshotted, backed",
		"up, kept across upgrades), created empty and owned by root: chown it in setup.",
	},
	"config": {"Files a person edits, and the service to restart after a change."},
	"logs":   {"Log files or directories, below /var/log, /var/db or /usr/local."},
	"setup": {
		"Run once in the jail after the packages and rc.conf, before the services: argv with",
		"an absolute program path, no shell, no network. pkg -r installs from the host, where",
		"the package's user does not exist, so the directories a package gives to its user",
		"come out owned by root: mkdir -p and chown them here, the data volumes too.",
	},
	"stop_timeout": {"seconds the jail may take to shut down cleanly before its processes are killed: a database that", "needs a minute to flush and close says 60 (boot.stop_timeout of the jail); leave it out for the default."},
	"sysvipc":      {"true only for a server that needs System V shared memory, semaphores or message", "queues (PostgreSQL's initdb does); the jail then gets namespaces of its own."},
	"health": {
		"How the installer checks that it runs: exactly one of tcp: PORT, http: {port, path,",
		"status} or exec: [argv in the jail], retried for wait_seconds (at most 300). null only",
		"for an app that starts none of its services; say why in the description.",
	},
	"access": {
		"What jailops app allow does in the jail besides the firewall rule: type postgresql makes",
		"a role and a database per grant and a line in a managed block of hba_file. Leave the key",
		"out otherwise; a daemon before 0.4.0 lists a definition that has it as invalid.",
	},
	"resources": {"Hints for the jail's limits (memory and disk sizes, cpu a count), not limits."},
	"notes":     {"Shown after the installation: the first-run steps and how to connect."},
}

// YAML writes the draft. File names in the header use the app name.
func (d Draft) YAML() []byte {
	a := d.App
	var b strings.Builder
	w := func(format string, args ...any) { fmt.Fprintf(&b, format, args...) }
	w("# %s: an app definition for the JailOps catalog, format version 1 (docs/apps.md).\n", a.Name)
	w("# Fill in what is marked; 'jailops app validate %s.yaml' lists each marked line left.\n", a.Name)
	w("# To try it on a host, copy %s.yaml and its icon into %s and run\n", a.Name, DefaultLocalDir)
	w("# 'jailops app install %s'.\n", a.Name)
	for _, l := range d.Header {
		w("#%s\n", prefixed(" ", l))
	}
	key := func(k string) {
		w("\n")
		for _, c := range sectionComments[k] {
			w("# %s\n", c)
		}
		if t := d.Todo[k]; t != "" {
			w("# %s: %s\n", TodoMarker, t)
		}
		w("%s:", k)
	}
	key("version")
	w(" %d\n", a.Version)
	key("name")
	w(" %s\n", scalar(a.Name))
	key("title")
	w(" %s\n", scalar(a.Title))
	key("summary")
	w(" %s\n", scalar(a.Summary))
	key("description")
	w("%s", block(a.Description, "  "))
	key("category")
	w(" %s\n", scalar(string(a.Category)))
	key("homepage")
	w(" %s\n", scalar(a.Homepage))
	key("license")
	w(" %s\n", scalar(a.License))
	key("icon")
	w(" %s\n", scalar(a.Icon))
	key("image")
	w("\n  os: %s\n  release_min: %s\n", scalar(a.Image.OS), quoted(a.Image.ReleaseMin))

	key("packages")
	if len(a.Packages) == 0 {
		w(" []\n")
	}
	for _, p := range a.Packages {
		w("\n  - name: %s\n    repo: %s", scalar(p.Name), scalar(orDefault(p.Repo, "ports")))
		if p.Version != "" {
			w("\n    version: %s", quoted(p.Version))
		}
	}
	if len(a.Packages) > 0 {
		w("\n")
	}

	key("services")
	if len(a.Services) == 0 {
		w(" []\n")
	}
	for _, s := range a.Services {
		w("\n  - name: %s\n", scalar(s.Name))
		if len(s.RC) > 0 {
			w("    rc:\n")
			for _, k := range sortedKeys(s.RC) {
				w("      %s: %s\n", k, quoted(s.RC[k]))
			}
		}
		w("    start: %t", s.Start == nil || *s.Start)
	}
	if len(a.Services) > 0 {
		w("\n")
	}

	key("ports")
	if len(a.Ports) == 0 {
		w(" []\n")
	}
	for _, p := range a.Ports {
		w("\n  - name: %s\n    port: %d\n    proto: %s\n", scalar(p.Name), p.Port, scalar(orDefault(p.Proto, "tcp")))
		if p.Description != "" {
			w("    description: %s\n", scalar(p.Description))
		}
		w("    expose: %t", p.Expose)
	}
	if len(a.Ports) > 0 {
		w("\n")
	}

	key("data")
	if len(a.Data) == 0 {
		w(" []\n")
	}
	for _, p := range a.Data {
		w("\n  - path: %s", scalar(p.Path))
		if p.Description != "" {
			w("\n    description: %s", scalar(p.Description))
		}
	}
	if len(a.Data) > 0 {
		w("\n")
	}

	key("config")
	if len(a.Config) == 0 {
		w(" []\n")
	}
	for _, c := range a.Config {
		w("\n  - path: %s", scalar(c.Path))
		if c.Description != "" {
			w("\n    description: %s", scalar(c.Description))
		}
		if c.Restart != "" {
			w("\n    restart: %s", scalar(c.Restart))
		}
	}
	if len(a.Config) > 0 {
		w("\n")
	}

	key("logs")
	if len(a.Logs) == 0 {
		w(" []\n")
	}
	for _, l := range a.Logs {
		w("\n  - name: %s\n    path: %s", scalar(l.Name), scalar(l.Path))
		if l.Description != "" {
			w("\n    description: %s", scalar(l.Description))
		}
	}
	if len(a.Logs) > 0 {
		w("\n")
	}

	key("setup")
	if len(a.Setup) == 0 {
		w(" []\n")
	} else {
		w("\n")
	}
	for _, argv := range a.Setup {
		w("  - %s\n", flowList(argv))
	}

	key("sysvipc")
	w(" %t\n", a.SysVIPC)

	if a.StopTimeout > 0 {
		key("stop_timeout")
		w(" %d\n", a.StopTimeout)
	}

	key("health")
	switch h := a.Health; {
	case h == nil:
		w(" null\n")
	case h.TCP != 0:
		w("\n  tcp: %d\n", h.TCP)
	case h.HTTP != nil:
		w("\n  http:\n    port: %d\n    path: %s\n", h.HTTP.Port, scalar(h.HTTP.Path))
		if h.HTTP.Status != 0 {
			w("    status: %d\n", h.HTTP.Status)
		}
	default:
		w("\n  exec: %s\n", flowList(h.Exec))
	}
	if a.Health != nil && a.Health.WaitSeconds != 0 {
		w("  wait_seconds: %d\n", a.Health.WaitSeconds)
	}

	if ac := a.Access; ac != nil {
		key("access")
		w("\n  type: %s\n  port: %s\n  service: %s\n  hba_file: %s\n", scalar(ac.Type), scalar(ac.Port), scalar(ac.Service), scalar(ac.HBAFile))
	}

	key("resources")
	r := a.Resources
	if r == (api.AppResources{}) {
		w(" {}\n")
	} else {
		w("\n")
		if r.Memory != "" {
			w("  memory: %s\n", size(r.Memory))
		}
		if r.Disk != "" {
			w("  disk: %s\n", size(r.Disk))
		}
		if r.CPU != "" {
			w("  cpu: %s\n", quoted(r.CPU))
		}
	}

	key("notes")
	w("%s", block(a.Notes, "  "))
	return []byte(b.String())
}

func orDefault(s, d string) string {
	if s == "" {
		return d
	}
	return s
}

func prefixed(p, s string) string {
	if s == "" {
		return ""
	}
	return p + s
}

var (
	plainRE    = regexp.MustCompile(`^[A-Za-z/][^\x00-\x1f\x7f"'#]*$`)
	flowCharRE = regexp.MustCompile(`[,\[\]{}]`)
	numberRE   = regexp.MustCompile(`^[-+.0-9]`)
)

// yamlWords are plain words a YAML reader takes for something else than a string.
var yamlWords = map[string]bool{"true": true, "false": true, "null": true, "yes": true, "no": true, "on": true, "off": true, "y": true, "n": true, "~": true}

func plain(s string) bool {
	return s != "" && plainRE.MatchString(s) && !strings.Contains(s, ": ") && !strings.HasSuffix(s, ":") &&
		strings.TrimSpace(s) == s && !yamlWords[strings.ToLower(s)] && !numberRE.MatchString(s)
}

// scalar writes a string for a block mapping: plain when that reads back as
// the same string, else double-quoted.
func scalar(s string) string {
	if plain(s) {
		return s
	}
	return quoted(s)
}

var sizeRE = regexp.MustCompile(`^[0-9]+[KMGTP]$`)

// size writes a size such as 512M plain, as the catalog does.
func size(s string) string {
	if sizeRE.MatchString(s) {
		return s
	}
	return scalar(s)
}

// quoted writes a double-quoted YAML string; Go's escapes are YAML's.
func quoted(s string) string { return strconv.Quote(s) }

// flowList writes an argv as a flow sequence: [/bin/mkdir, -p, /var/db/x].
func flowList(argv []string) string {
	l := make([]string, len(argv))
	for i, a := range argv {
		switch {
		case plain(a) && !flowCharRE.MatchString(a) && !strings.Contains(a, ":"):
			l[i] = a
		case strings.HasPrefix(a, "-") && len(a) > 1 && plain("x"+a) && !flowCharRE.MatchString(a) && !strings.Contains(a, ":") && !numberRE.MatchString(a[1:]):
			l[i] = a // a flag
		default:
			l[i] = quoted(a)
		}
	}
	return "[" + strings.Join(l, ", ") + "]"
}

// block writes text as a literal block under a key, or "" when empty. Text
// that a literal block cannot carry as it is (a first line that starts with
// white space) is double-quoted instead.
func block(s, indent string) string {
	if s == "" {
		return " \"\"\n"
	}
	if strings.HasPrefix(s, " ") || strings.HasPrefix(s, "\t") || strings.HasPrefix(s, "\n") || strings.ContainsAny(s, "\r") {
		return " " + quoted(s) + "\n"
	}
	head := " |"
	body := s
	switch {
	case strings.HasSuffix(s, "\n\n"):
		head = " |+"
	case strings.HasSuffix(s, "\n"):
	default:
		head = " |-"
		body += "\n"
	}
	var b strings.Builder
	b.WriteString(head + "\n")
	for _, l := range strings.Split(strings.TrimSuffix(body, "\n"), "\n") {
		if l == "" {
			b.WriteString("\n")
		} else {
			b.WriteString(indent + l + "\n")
		}
	}
	return b.String()
}
