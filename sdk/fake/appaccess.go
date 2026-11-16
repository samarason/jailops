package fake

import (
	"crypto/rand"
	"net"
	"net/http"
	"net/netip"
	"regexp"
	"slices"
	"sort"
	"strconv"
	"strings"

	"jailops.net/jailops/sdk/api"
)

// fakeAccess is who may connect to one installed app: the grants and the
// roles made for them (by name), as the daemon keeps them, without a password.
type fakeAccess struct {
	closed bool
	grants []api.AppAccessGrant
	roles  map[string]bool // role -> has login
}

var fakeDBName = regexp.MustCompile(`^[a-z][a-z0-9_]{0,62}$`)

// SeedAppGrant adds a grant to an installed app (demo data, tests). The jail
// must have been installed from the catalog.
func (s *Server) SeedAppGrant(project, jail string, g api.AppAccessGrant) {
	s.mu.Lock()
	defer s.mu.Unlock()
	k := s.jails.keyIn(project, jail)
	a := s.access[k]
	if a == nil {
		a = &fakeAccess{closed: true, roles: map[string]bool{}}
		s.access[k] = a
	}
	if g.Role != "" {
		a.roles[g.Role] = true
	}
	a.grants = append(a.grants, g)
}

// appOf returns the installed jail named in the request and its definition.
func (s *Server) appOf(r *http.Request, name string) (string, *api.Jail, *api.App, *api.Error) {
	key, j := s.jails.find(r, name)
	if j == nil {
		return "", nil, nil, notFound("jail", name)
	}
	app := j.Metadata.Labels[api.LabelApp]
	if app == "" {
		return "", nil, nil, api.Errorf(api.CodeInvalid, "jail %q was not installed from the catalog (it has no label %s)", name, api.LabelApp)
	}
	var def *api.App
	if e := s.apps[app]; e != nil && e.err == "" {
		d := e.detail.Definition
		def = &d
	}
	return key, j, def, nil
}

func fakeDefaultPorts(def *api.App) []string {
	out := []string{}
	if def == nil {
		return out
	}
	for _, p := range def.Ports {
		if def.Access != nil && p.Name != def.Access.Port {
			continue
		}
		out = append(out, strconv.Itoa(p.Port)+"/"+p.Proto)
	}
	return out
}

func (s *Server) handleAppAccess(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")
	s.mu.Lock()
	defer s.mu.Unlock()
	key, j, def, e := s.appOf(r, name)
	if e != nil {
		writeErr(w, e)
		return
	}
	out := api.AppAccess{Jail: name, Project: j.Metadata.Project, App: j.Metadata.Labels[api.LabelApp], Policy: "app-" + name,
		Ports: fakeDefaultPorts(def), Grants: []api.AppAccessGrant{}}
	if def != nil && def.Access != nil {
		out.Type = def.Access.Type
	}
	if a := s.access[key]; a != nil {
		out.Closed = a.closed
		out.Grants = append(out.Grants, a.grants...)
	} else {
		out.Warnings = append(out.Warnings, "the jail is open to its network: it was installed before app access, and its first allow closes it to every other source")
	}
	if j.Status.Power != api.PowerRunning {
		out.Warnings = append(out.Warnings, "the jail is stopped: its anchor is not loaded and pg_hba.conf is not checked")
	}
	writeSync(w, 200, out)
}

// fakeSource resolves a source the way the daemon does, from the fake's jails and address sets.
func (s *Server) fakeSource(project, self, src string) (canonical, kind string, addrs []string, from []string, e *api.Error) {
	addrsOf := func(j *api.Jail) []string {
		var out []string
		for _, n := range j.Spec.Network {
			for _, a := range []string{n.IPv4, n.IPv6} {
				if p, err := netip.ParsePrefix(a); err == nil {
					out = append(out, p.Addr().String())
				} else if ad, err := netip.ParseAddr(a); err == nil {
					out = append(out, ad.String())
				}
			}
		}
		return out
	}
	jail := func(n string) (string, string, []string, []string, *api.Error) {
		j := s.jails.items[s.jails.keyIn(project, n)]
		if j == nil {
			return "", "", nil, nil, notFound("jail", n)
		}
		if n == self {
			return "", "", nil, nil, api.Errorf(api.CodeInvalid, "a jail always reaches itself; name another source")
		}
		a := addrsOf(j)
		if len(a) == 0 {
			return "", "", nil, nil, api.Errorf(api.CodeInvalid, "jail %q has no address to allow", n)
		}
		var pf []string
		for _, x := range a {
			ad := netip.MustParseAddr(x)
			pf = append(pf, netip.PrefixFrom(ad, ad.BitLen()).String())
		}
		return "jail:" + n, api.AccessSourceJail, pf, []string{"jail:" + n}, nil
	}
	switch {
	case src == "host":
		return "host", api.AccessSourceHost, []string{"10.20.0.1/32"}, []string{"10.20.0.1"}, nil
	case strings.HasPrefix(src, "@"):
		n := src[1:]
		return "", "", nil, nil, api.Errorf(api.CodeInvalid, "source %q: @ is not used: write jail:%s or set:%s", src, n, n)
	case strings.HasPrefix(src, "set:"):
		rest := src[4:]
		if set := s.addrsets.items[s.addrsets.keyIn(project, rest)]; set != nil {
			return "set:" + rest, api.AccessSourceSet, set.Spec.Members(), []string{"set:" + rest}, nil
		}
		return "", "", nil, nil, api.Errorf(api.CodeNotFound, "address set %q not found in project %s", rest, project)
	case strings.HasPrefix(src, "jail:"):
		return jail(src[5:])
	}
	if p, err := netip.ParsePrefix(src); err == nil {
		return p.Masked().String(), api.AccessSourceCIDR, []string{p.Masked().String()}, []string{p.Masked().String()}, nil
	}
	if a, err := netip.ParseAddr(src); err == nil {
		return a.String(), api.AccessSourceCIDR, []string{netip.PrefixFrom(a, a.BitLen()).String()}, []string{a.String()}, nil
	}
	return "", "", nil, nil, api.Errorf(api.CodeInvalid, "source %q is not an address, a prefix, jail:NAME, set:NAME or host", src)
}

func fakePassword() string {
	const abc = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"
	b := make([]byte, 32)
	_, _ = rand.Read(b)
	for i := range b {
		b[i] = abc[int(b[i])%len(abc)]
	}
	return string(b)
}

func (s *Server) handleAppAllow(w http.ResponseWriter, r *http.Request) {
	req, e := decode[api.AppAllow](r)
	if e != nil {
		writeErr(w, e)
		return
	}
	name := r.PathValue("name")
	s.mu.Lock()
	defer s.mu.Unlock()
	key, j, def, e := s.appOf(r, name)
	if e != nil {
		writeErr(w, e)
		return
	}
	project := j.Metadata.Project
	canonical, kind, prefixes, from, e := s.fakeSource(project, name, req.Source)
	if e != nil {
		writeErr(w, e)
		return
	}
	ports := req.Ports
	if len(ports) == 0 {
		ports = fakeDefaultPorts(def)
	}
	if len(ports) == 0 {
		writeErr(w, api.Errorf(api.CodeInvalid, "app %s declares no ports; name one with --port N[/tcp|udp]", j.Metadata.Labels[api.LabelApp]))
		return
	}
	var norm []string
	for _, p := range ports {
		if !strings.Contains(p, "/") {
			p += "/tcp"
		}
		norm = append(norm, p)
	}
	// by protocol, then by number, as the daemon sorts them
	sort.Slice(norm, func(i, j int) bool {
		ni, pi, _ := strings.Cut(norm[i], "/")
		nj, pj, _ := strings.Cut(norm[j], "/")
		if pi != pj {
			return pi < pj
		}
		a, _ := strconv.Atoi(ni)
		b, _ := strconv.Atoi(nj)
		return a < b
	})
	g := api.AppAccessGrant{Source: canonical, SourceKind: kind, Addresses: prefixes, Ports: slices.Compact(norm),
		CreatedAt: s.now(), CreatedBy: s.info(r).id.Name}
	byProto := map[string][]string{}
	for _, p := range g.Ports {
		n, proto, _ := strings.Cut(p, "/")
		byProto[proto] = append(byProto[proto], n)
	}
	var protos []string
	for p := range byProto {
		protos = append(protos, p)
	}
	sort.Strings(protos)
	for _, p := range protos {
		g.Rules = append(g.Rules, "allow in "+p+" from "+strings.Join(from, ",")+" to port "+strings.Join(byProto[p], ","))
	}
	res := api.AppAllowResult{Jail: name, DryRun: req.DryRun}
	a := s.access[key]
	if a == nil {
		a = &fakeAccess{roles: map[string]bool{}}
		res.Notes = append(res.Notes, "jail "+name+" was open to its network until now (installed before app access); from now on it is closed to every source that is not allowed")
	}
	i := slices.IndexFunc(a.grants, func(x api.AppAccessGrant) bool { return x.Source == canonical })
	password := ""
	if def != nil && def.Access != nil {
		db := req.Database
		if db == "" && i >= 0 {
			db = a.grants[i].Database
		}
		if db == "" && kind == api.AccessSourceJail {
			db = strings.ReplaceAll(canonical[strings.LastIndex(canonical, "/")+1:], "-", "_")
			db = strings.TrimPrefix(db, "jail:")
		}
		if db == "" {
			writeErr(w, api.Errorf(api.CodeInvalid, "name the database of this grant with --db NAME (a source that is not a jail has no default)"))
			return
		}
		if !fakeDBName.MatchString(db) || db == "postgres" || strings.HasPrefix(db, "pg_") {
			writeErr(w, api.Errorf(api.CodeInvalid, "database name %q must match ^[a-z][a-z0-9_]{0,62}$ and not be reserved", db))
			return
		}
		if i >= 0 && a.grants[i].Database != db {
			writeErr(w, api.Errorf(api.CodeConflict, "%s already has access to database %s", canonical, a.grants[i].Database).WithHint("deny it first to give it another database"))
			return
		}
		if j.Status.Power != api.PowerRunning {
			writeErr(w, api.Errorf(api.CodeBusy, "jail %q is stopped; the role and the database are made with psql in it", name).WithHint("start it with jailops start "+name))
			return
		}
		g.Database, g.Role, g.RoleCreated, g.DatabaseCreated = db, db, true, true
		for _, p := range prefixes {
			g.HBA = append(g.HBA, "host "+db+" "+db+" "+p+" scram-sha-256")
		}
		login, known := a.roles[db]
		if !known || !login || req.Rotate {
			if known {
				res.SQL = append(res.SQL, `ALTER ROLE "`+db+`" LOGIN PASSWORD '<generated, shown once>';`)
			} else {
				res.SQL = append(res.SQL, `CREATE ROLE "`+db+`" LOGIN PASSWORD '<generated, shown once>';`, `CREATE DATABASE "`+db+`" OWNER "`+db+`";`)
			}
			password = fakePassword()
		}
		res.Steps = append(res.Steps, "in the jail, as postgres: psql with the statements on standard input")
		res.Steps = append(res.Steps, def.Access.HBAFile+": the managed block gets "+strings.Join(g.HBA, "; ")+"; then the server reloads it")
	} else {
		note := "only the firewall changed: the app must itself listen on the jail's address and accept the client (see its configuration files with jailops app info " + j.Metadata.Labels[api.LabelApp] + ")"
		if j.Metadata.Labels[api.LabelApp] == "valkey" {
			note += "; Valkey binds 127.0.0.1 with protected-mode yes until bind and protected-mode in /usr/local/etc/valkey.conf are changed, and requirepass should be set before it is reachable"
		}
		res.Notes = append(res.Notes, note)
	}
	res.Steps = append([]string{"firewall policy app-" + name + ": " + strings.Join(g.Rules, "; ")}, res.Steps...)
	if i >= 0 {
		g.CreatedAt, g.CreatedBy = a.grants[i].CreatedAt, a.grants[i].CreatedBy
	}
	if req.DryRun {
		res.Grant, res.Changed = g, true
		writeSync(w, 200, res)
		return
	}
	s.access[key] = a
	a.closed = true
	same := i >= 0 && slices.Equal(a.grants[i].Ports, g.Ports) && slices.Equal(a.grants[i].Addresses, g.Addresses)
	if i >= 0 {
		a.grants[i] = g
	} else {
		a.grants = append(a.grants, g)
	}
	if g.Role != "" {
		a.roles[g.Role] = true
	}
	res.Grant = g
	res.Changed = !same || password != ""
	if password != "" {
		host := ""
		if addrs := j.Status.Addresses; len(addrs) > 0 {
			host = addrs[0]
		}
		if p, err := netip.ParsePrefix(host); err == nil {
			host = p.Addr().String()
		}
		res.ConnectionString = "postgres://" + g.Role + ":" + password + "@" + net.JoinHostPort(host, "5432") + "/" + g.Database + "?sslmode=disable"
		res.Notes = append(res.Notes, "the connection string is shown once and stored nowhere; jailops app allow "+name+" from "+canonical+" --rotate makes a new password")
	} else if g.Role != "" {
		res.Notes = append(res.Notes, "role "+g.Role+" exists: its password was shown when it was made; --rotate makes a new one")
	}
	if !res.Changed {
		res.Notes = append(res.Notes, "nothing changed: the grant exists as it is")
	}
	s.emitIn(project, "app-access-updated", "/api/v1/jails/"+name)
	writeSync(w, 200, res)
}

func (s *Server) handleAppDeny(w http.ResponseWriter, r *http.Request) {
	req, e := decode[api.AppDeny](r)
	if e != nil {
		writeErr(w, e)
		return
	}
	name := r.PathValue("name")
	s.mu.Lock()
	defer s.mu.Unlock()
	key, j, _, e := s.appOf(r, name)
	if e != nil {
		writeErr(w, e)
		return
	}
	project := j.Metadata.Project
	canonical := req.Source
	if p, err := netip.ParsePrefix(canonical); err == nil {
		canonical = p.Masked().String()
		if p.Bits() == p.Addr().BitLen() {
			canonical = p.Addr().String()
		}
	}
	res := api.AppDenyResult{Jail: name, DryRun: req.DryRun}
	a := s.access[key]
	i := -1
	if a != nil {
		i = slices.IndexFunc(a.grants, func(x api.AppAccessGrant) bool { return x.Source == canonical })
	}
	if i < 0 {
		res.Notes = append(res.Notes, "nothing changed: "+canonical+" has no access to "+name)
		writeSync(w, 200, res)
		return
	}
	g := a.grants[i]
	res.Removed, res.Changed = g, true
	for _, rule := range g.Rules {
		res.Steps = append(res.Steps, "firewall policy app-"+name+": remove "+rule)
	}
	if g.Role != "" {
		if j.Status.Power != api.PowerRunning && !req.DryRun {
			writeErr(w, api.Errorf(api.CodeBusy, "jail %q is stopped; the role and pg_hba.conf are changed with psql in it", name).WithHint("start it with jailops start "+name))
			return
		}
		used := false
		for k, o := range a.grants {
			used = used || (k != i && o.Role == g.Role)
		}
		switch {
		case used:
			res.Notes = append(res.Notes, "role "+g.Role+" stays: another grant uses it")
		case req.DropRole:
			res.SQL = []string{`REASSIGN OWNED BY "` + g.Role + `" TO postgres;`, `DROP OWNED BY "` + g.Role + `";`, `DROP ROLE IF EXISTS "` + g.Role + `";`}
			res.Notes = append(res.Notes, "role "+g.Role+" is dropped; what it owned now belongs to postgres and database "+g.Database+" is kept")
		default:
			res.SQL = []string{`ALTER ROLE "` + g.Role + `" NOLOGIN PASSWORD NULL;`}
			res.Notes = append(res.Notes, "role "+g.Role+" keeps its database and loses its login and password; --drop-role drops it")
		}
	}
	if req.DryRun {
		writeSync(w, 200, res)
		return
	}
	a.grants = slices.Delete(a.grants, i, i+1)
	if g.Role != "" {
		a.roles[g.Role] = false
	}
	s.emitIn(project, "app-access-updated", "/api/v1/jails/"+name)
	writeSync(w, 200, res)
}
