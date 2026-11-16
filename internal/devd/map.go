package devd

import "strings"

// Event is what JailOps publishes for a record: a lifecycle event of the host or of one jail.
type Event struct {
	Action  string // host-zfs-error, host-zfs-pool, host-link-down, host-link-up, jail-limit-hit
	Source  string // /api/v1/host, or /api/v1/jails/NAME for a jail
	Project string // the project of the jail; empty for the host, whose events global identities see
	Detail  string // one short line for a person
}

// Mapper says which records are of interest. Both functions come from the service, which knows the networks and the
// jails; either may be nil, and a record that needs the missing one is then ignored.
type Mapper struct {
	// Link describes an interface JailOps owns or depends on ("uplink em0"); ok is false
	// for any other interface, and for the epair of a jail, whose ends come and go with every start.
	Link func(iface string) (what string, ok bool)
	// Jail resolves the name the kernel knows a jail by (project_jail) to its project and name.
	Jail func(osName string) (project, name string, ok bool)
}

// Map turns a record into an event, or reports false when the record is of no interest.
func (m Mapper) Map(r Record) (Event, bool) {
	switch r.Get("system") {
	case "ZFS":
		return mapZFS(r)
	case "IFNET":
		return m.mapLink(r)
	case "RCTL":
		return m.mapLimit(r)
	}
	return Event{}, false
}

func mapZFS(r Record) (Event, bool) {
	typ := r.Get("type")
	pool := word(r.Get("pool"))
	if pool == "" {
		pool = word(r.Get("pool_guid"))
	}
	where := ""
	if pool != "" {
		where = "pool " + pool + ": "
	}
	switch {
	case strings.HasPrefix(typ, "ereport.fs.zfs."):
		kind := strings.TrimPrefix(typ, "ereport.fs.zfs.")
		if !zfsErrorKind(kind) {
			return Event{}, false
		}
		d := where + strings.ReplaceAll(kind, "_", " ")
		if p := word(r.Get("vdev_path")); p != "" {
			d += " on " + p
		}
		return Event{Action: "host-zfs-error", Source: "/api/v1/host", Detail: d}, true
	case typ == "resource.fs.zfs.statechange":
		return Event{Action: "host-zfs-pool", Source: "/api/v1/host", Detail: where + "a device changed state"}, true
	case typ == "resource.fs.zfs.removed":
		return Event{Action: "host-zfs-pool", Source: "/api/v1/host", Detail: where + "a device was removed"}, true
	case typ == "misc.fs.zfs.scrub_finish":
		return Event{Action: "host-zfs-pool", Source: "/api/v1/host", Detail: where + "scrub finished"}, true
	case typ == "misc.fs.zfs.scrub_abort":
		return Event{Action: "host-zfs-pool", Source: "/api/v1/host", Detail: where + "scrub aborted"}, true
	}
	return Event{}, false
}

// zfsErrorKind are the error reports of a pool or a device that an operator acts on.
func zfsErrorKind(k string) bool {
	switch k {
	case "checksum", "io", "data", "io_failure", "probe_failure", "zpool", "log_replay", "config_cache_write":
		return true
	}
	return strings.HasPrefix(k, "vdev.")
}

func (m Mapper) mapLink(r Record) (Event, bool) {
	var state string
	switch r.Get("type") {
	case "LINK_UP":
		state = "up"
	case "LINK_DOWN":
		state = "down"
	default:
		return Event{}, false
	}
	iface := word(r.Get("subsystem"))
	if iface == "" || m.Link == nil {
		return Event{}, false
	}
	what, ok := m.Link(iface)
	if !ok {
		return Event{}, false
	}
	return Event{Action: "host-link-" + state, Source: "/api/v1/host", Detail: what + " link " + state}, true
}

// mapLimit reads the notification of a resource limit with the action devctl:
//
//	!system=RCTL subsystem=rule type=matched rule=jail:alpha_web:memoryuse:devctl=... jail=alpha_web ...
//
// The jail is the field jail when the record has it and otherwise the second part of the rule.
func (m Mapper) mapLimit(r Record) (Event, bool) {
	if r.Get("subsystem") != "rule" || r.Get("type") != "matched" || m.Jail == nil {
		return Event{}, false
	}
	parts := strings.Split(r.Get("rule"), ":")
	name := word(r.Get("jail"))
	if name == "" && len(parts) >= 2 && parts[0] == "jail" {
		name = word(parts[1])
	}
	if name == "" {
		return Event{}, false
	}
	project, jail, ok := m.Jail(name)
	if !ok {
		return Event{}, false
	}
	resource := "resource"
	if len(parts) >= 3 && parts[0] == "jail" {
		if w := word(parts[2]); w != "" {
			resource = w
		}
	}
	return Event{Action: "jail-limit-hit", Source: "/api/v1/jails/" + jail, Project: project,
		Detail: "the limit " + resource + " of the jail was reached"}, true
}

// word keeps a value of a record to what is safe in a line of text of an event: printable ASCII without spaces and at
// most 80 characters.
func word(s string) string {
	var b strings.Builder
	for _, r := range s {
		if r > ' ' && r < 0x7f && b.Len() < 80 {
			b.WriteRune(r)
		}
	}
	return b.String()
}
