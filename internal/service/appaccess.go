package service

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"os"
	"slices"
	"sort"
	"strings"
	"time"

	"jailops.net/jailops/internal/apps"
	"jailops.net/jailops/internal/sys/jailos"
	"jailops.net/jailops/internal/validate"
	"jailops.net/jailops/sdk/api"
)

// Who may connect to an installed app (docs/apps.md, "Who may connect"). An
// app's jail is closed when it is installed: its managed firewall policy
// app-<jail> denies every inbound connection. An allow adds a rule for one
// source to that policy and, for an app whose definition has an access block
// (postgresql), makes a role and a database with psql in the jail and a line
// in a managed block of pg_hba.conf. A deny takes it all back. The grants are
// a registry in the state store (kind AppAccess, one object per app jail): it
// records which roles and databases JailOps made, so it never changes or
// drops one it did not make, and it never holds a password.

// accessRecord is the stored registry of one app jail.
type accessRecord struct {
	// Type, HBAFile, Service and Port are the definition's access block as it
	// was at the first grant, so a deny works when the definition changed.
	Type    string `json:"type,omitempty"`
	HBAFile string `json:"hba_file,omitempty"`
	Service string `json:"service,omitempty"`
	Port    int    `json:"port,omitempty"`
	// Roles are the roles JailOps made (each with the database of its name).
	Roles  []accessRole  `json:"roles,omitempty"`
	Grants []accessGrant `json:"grants"`
}

type accessRole struct {
	Name            string `json:"name"`
	DatabaseCreated bool   `json:"database_created,omitempty"`
	// Login is false after a deny that kept the role.
	Login bool `json:"login"`
	// Unfinished: the allow that set its password stopped before the end, so the password was never shown. The
	// role is in the registry from the moment psql made it; the next allow sets a new password and finishes.
	Unfinished bool `json:"unfinished,omitempty"`
}

type accessGrant struct {
	Source     string `json:"source"`
	Kind       string `json:"kind"`
	SourceName string `json:"source_name,omitempty"`
	// From are the firewall endpoints of the rule (jail:web and set:office stay references, read at every render);
	// Prefixes are what the client authentication lines name, a copy made when the grant was.
	From      []string  `json:"from"`
	Prefixes  []string  `json:"prefixes,omitempty"`
	Ports     []string  `json:"ports"`
	Database  string    `json:"database,omitempty"`
	HBA       []string  `json:"hba,omitempty"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at,omitzero"`
	CreatedBy string    `json:"created_by,omitempty"`
}

func (s *Service) accKind() kindStore[accessRecord] {
	return newProjectKindStore[accessRecord](s, api.KindAppAccess, api.ScopeHost, "app-access", "/api/v1/jails")
}

// accessRand is where passwords and salts come from.
var accessRand io.Reader = rand.Reader

// appTarget is an installed app a request names.
type appTarget struct {
	p    project
	key  string
	jail api.Jail
	app  string
	def  *api.App // nil when the definition is gone or invalid
	rec  accessRecord
	has  bool // the registry object exists
}

func (s *Service) appTarget(ctx context.Context, name string) (appTarget, error) {
	p, key, err := s.jailRef(ctx, name)
	if err != nil {
		return appTarget{}, err
	}
	j, err := s.getByKey(ctx, key)
	if err != nil {
		return appTarget{}, err
	}
	t := appTarget{p: p, key: key, jail: j, app: j.Metadata.Labels[api.LabelApp]}
	if t.app == "" {
		return t, invalid("jail %q was not installed from the catalog (it has no label %s)", name, api.LabelApp).
			WithHint("access is managed for installed apps; for any other jail write a firewall policy (jailops firewall policy)")
	}
	if e, ok, err := s.findApp(t.app); err == nil && ok && e.Err == nil {
		def := e.App
		t.def = &def
	}
	if o, err := s.accKind().p(p.Meta.Name).get(j.Metadata.Name); err == nil {
		t.rec, t.has = o.Spec, true
	} else if !api.IsCode(err, api.CodeNotFound) {
		return t, err
	}
	return t, nil
}

// accessType is the access block that applies: the registry's once there is
// one, the definition's before.
func (t appTarget) access() *api.AppAccessDef {
	if t.rec.Type != "" {
		port := ""
		if t.def != nil && t.def.Access != nil {
			port = t.def.Access.Port
		}
		return &api.AppAccessDef{Type: t.rec.Type, HBAFile: t.rec.HBAFile, Service: t.rec.Service, Port: port}
	}
	if t.def != nil {
		return t.def.Access
	}
	return nil
}

func (t appTarget) dbPort() int {
	if t.rec.Port != 0 {
		return t.rec.Port
	}
	if t.def != nil && t.def.Access != nil {
		for _, p := range t.def.Ports {
			if p.Name == t.def.Access.Port {
				return p.Port
			}
		}
	}
	return 5432
}

func findGrant(gs []accessGrant, source string) int {
	return slices.IndexFunc(gs, func(g accessGrant) bool { return g.Source == source })
}

func (r accessRecord) role(name string) (accessRole, int) {
	i := slices.IndexFunc(r.Roles, func(x accessRole) bool { return x.Name == name })
	if i < 0 {
		return accessRole{}, -1
	}
	return r.Roles[i], i
}

// resolved is a source looked up in the project.
type resolvedSource struct {
	canonical, kind, name string
	from                  []string
	prefixes              []netip.Prefix
}

// resolveSource looks a parsed source up: jail:NAME is a jail of the project, set:NAME an address set of it, host the
// gateway addresses of the app jail's networks. The firewall rule keeps jail:NAME or set:NAME, which is read at every
// render; prefixes are what pg_hba.conf gets, a copy.
func (s *Service) resolveSource(ctx context.Context, t appTarget, src apps.Source) (resolvedSource, error) {
	proj := t.p.Meta.Name
	out := resolvedSource{canonical: src.Canonical(), kind: src.Kind}
	switch src.Kind {
	case api.AccessSourceHost:
		for _, a := range gatewayAddrs(s, &t.jail) {
			out.from = append(out.from, a.String())
			out.prefixes = append(out.prefixes, apps.HostPrefix(a))
		}
		if len(out.from) == 0 {
			return out, invalid("the networks of jail %q have no gateway address the host connects from", t.jail.Metadata.Name)
		}
		return out, nil
	case api.AccessSourceCIDR:
		out.from = []string{src.Prefix.String()}
		if src.Prefix.Bits() == src.Prefix.Addr().BitLen() {
			out.from = []string{src.Prefix.Addr().String()}
		}
		out.prefixes = []netip.Prefix{src.Prefix}
		return out, nil
	case api.AccessSourceSet:
		sets, err := s.allSets(proj)
		if err != nil {
			return out, err
		}
		if _, ok := sets[src.Name]; !ok {
			return out, api.Errorf(api.CodeNotFound, "address set %q not found in project %s", src.Name, proj).
				WithHint("jailops firewall address-set list shows the names")
		}
		prefixes, err := s.setPrefixes(proj, src.Name)
		if err != nil {
			return out, err
		}
		out.name, out.from, out.prefixes = src.Name, []string{"set:" + src.Name}, prefixes
		return out, nil
	}
	key, kerr := validate.QualifiedName(proj, src.Name)
	if kerr != nil {
		return out, notFound("jail", src.Name)
	}
	if _, err := s.jailSnapshot(key); err != nil {
		return out, api.Errorf(api.CodeNotFound, "jail %q not found in project %s", src.Name, proj).
			WithHint("jailops list shows the names")
	}
	if key == t.key {
		return out, invalid("a jail always reaches itself; name another source")
	}
	prefixes, err := s.jailPrefixes(proj, src.Name)
	if err != nil {
		return out, err
	}
	if len(prefixes) == 0 {
		return out, invalid("jail %q has no address to allow", src.Name)
	}
	out.name, out.from, out.prefixes = src.Name, []string{"jail:" + src.Name}, prefixes
	return out, nil
}

// jailPrefixes are the addresses of a jail of the project as /32 and /128 prefixes.
func (s *Service) jailPrefixes(project, name string) ([]netip.Prefix, error) {
	key, err := validate.QualifiedName(project, name)
	if err != nil {
		return nil, notFound("jail", name)
	}
	j, err := s.jailSnapshot(key)
	if err != nil {
		return nil, notFound("jail", name)
	}
	var out []netip.Prefix
	for _, a := range jailAddrs(s.effective(j)) {
		out = append(out, apps.HostPrefix(a))
	}
	return out, nil
}

// setPrefixes are the members of an address set of the project, jails and other sets followed, as prefixes.
func (s *Service) setPrefixes(project, name string) ([]netip.Prefix, error) {
	sets, err := s.allSets(project)
	if err != nil {
		return nil, err
	}
	members, err := validate.FlattenSet(name, sets, s.projectJailAddrs(project))
	if err != nil {
		return nil, err
	}
	var out []netip.Prefix
	for _, m := range members {
		if pf, err := netip.ParsePrefix(m); err == nil {
			out = append(out, pf.Masked())
		} else if a, err := netip.ParseAddr(m); err == nil {
			out = append(out, apps.HostPrefix(a))
		}
	}
	return out, nil
}

// grantRules are the inbound rules of a grant in the app's policy: one per protocol.
func grantRules(g accessGrant) []api.FirewallRule {
	byProto := map[string][]string{}
	for _, p := range g.Ports {
		num, proto, _ := strings.Cut(p, "/")
		byProto[proto] = append(byProto[proto], num)
	}
	var out []api.FirewallRule
	for _, proto := range sortedKeys(byProto) {
		out = append(out, api.FirewallRule{Name: apps.AccessRuleName(g.Source, proto), Action: "allow", Direction: "in", Proto: proto,
			From: slices.Clone(g.From), Ports: byProto[proto]})
	}
	return out
}

func ruleNames(rs []api.FirewallRule) []string {
	var out []string
	for _, r := range rs {
		out = append(out, r.Name)
	}
	return out
}

// accessPolicy returns the managed policy of a jail; ok is false when there is none.
func (s *Service) accessPolicy(project, jail string) (object[api.FirewallPolicySpec], bool, error) {
	o, err := s.polKind.p(project).get(apps.AccessPolicyName(jail))
	if err != nil {
		if api.IsCode(err, api.CodeNotFound) {
			return o, false, nil
		}
		return o, false, err
	}
	if o.Meta.ManagedBy != api.AppAccessManagedBy {
		return o, false, api.Errorf(api.CodeConflict, "firewall policy %q exists and is not managed by app access", o.Meta.Name).
			WithHint("rename or delete that policy; app access keeps the policy app-<jail> of each app")
	}
	return o, true, nil
}

// writeAccessPolicy changes the managed policy of a jail: the rules named in
// drop go and add comes in (sorted by name). The policy always says its
// defaults: deny inbound, allow outbound. It reports whether anything changed.
func (s *Service) writeAccessPolicy(ctx context.Context, project, jail string, drop []string, add []api.FirewallRule, dry bool) (bool, error) {
	name := apps.AccessPolicyName(jail)
	if err := validate.Name("policy", name); err != nil {
		return false, invalid("the jail name %q is too long for its access policy %s", jail, name)
	}
	cur, ok, err := s.accessPolicy(project, jail)
	if err != nil {
		return false, err
	}
	next := cur.Spec
	if !ok {
		next = api.FirewallPolicySpec{}
	}
	next.DefaultIn, next.DefaultOut = "deny", "allow"
	if next.Comment == "" {
		next.Comment = "who may connect to " + jail + " (managed by app access)"
	}
	gone := map[string]bool{}
	for _, n := range drop {
		gone[n] = true
	}
	for _, r := range add {
		gone[r.Name] = true
	}
	var rules []api.FirewallRule
	for _, r := range next.Rules {
		if !gone[r.Name] {
			rules = append(rules, r)
		}
	}
	rules = append(rules, add...)
	sort.SliceStable(rules, func(i, j int) bool { return rules[i].Name < rules[j].Name })
	next.Rules = rules
	if ok && jsonEq(next, cur.Spec) {
		return false, nil
	}
	if dry {
		return true, nil
	}
	ks := s.polKind.p(project)
	sets, err := s.allRefs(project)
	if err != nil {
		return false, err
	}
	if err := s.checkPolicy(ctx, name, next, sets); err != nil {
		return false, err
	}
	mb := api.AppAccessManagedBy
	labels := map[string]string{api.LabelApp + ".access": jail}
	if ok {
		_, err = ks.update(ctx, name, AnyGeneration, labels, &mb, next)
	} else {
		_, err = ks.create(ctx, api.ObjectMeta{Name: name, Labels: labels, ManagedBy: mb}, next)
	}
	if err != nil {
		return false, err
	}
	s.kick()
	return true, nil
}

// closeApp creates the closed policy of a freshly installed app (the
// installation's step close-firewall).
func (s *Service) closeApp(ctx context.Context, project, jail string) error {
	_, err := s.writeAccessPolicy(ctx, project, jail, nil, nil, false)
	return err
}

// psql runs statements with psql as postgres in the jail, on standard input:
// nothing of them is in a process list.
func (s *Service) psql(ctx context.Context, key, db string, st []apps.Statement) ([]byte, error) {
	if s.d.Jails == nil {
		return nil, api.Errorf(api.CodeUnsupported, "this daemon cannot run commands in jails")
	}
	argv := apps.PsqlArgv(db)
	res, err := s.d.Jails.Exec(ctx, key, jailos.ExecOpts{Argv: argv, User: apps.PsqlUser, Stdin: strings.NewReader(apps.Script(st)), Timeout: 2 * time.Minute})
	if err != nil {
		return res.Stdout, fmt.Errorf("psql -d %s as %s: %w: %s", db, apps.PsqlUser, err, tailOf(append(append([]byte(nil), res.Stdout...), res.Stderr...)))
	}
	return res.Stdout, nil
}

// hbaLines are the lines of every grant of a record.
func hbaLines(gs []accessGrant) []string {
	var out []string
	for _, g := range gs {
		out = append(out, g.HBA...)
	}
	return out
}

// writeHBA puts the managed block into the jail's pg_hba.conf, gives the file
// back to postgres and has the server read it again. It reports whether the
// file changed.
func (s *Service) writeHBA(ctx context.Context, key, file string, lines []string) (bool, error) {
	path := s.rootMount(key) + file
	cur, err := s.d.Files.ReadFile(ctx, path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) || api.IsCode(err, api.CodeNotFound) {
			return false, fmt.Errorf("%s does not exist in the jail: is the cluster initialised?", file)
		}
		return false, fmt.Errorf("read %s: %w", file, err)
	}
	next, err := apps.SetHBABlock(string(cur), lines)
	if err != nil {
		return false, invalid("%s: %v", file, err)
	}
	if next == string(cur) {
		return false, nil
	}
	if err := s.d.Files.WriteAtomic(ctx, path, []byte(next)); err != nil {
		return false, fmt.Errorf("write %s: %w", file, err)
	}
	for _, argv := range [][]string{apps.HBAOwnerArgv(file), apps.HBAModeArgv(file)} {
		if _, err := s.runInJail(ctx, key, time.Minute, argv...); err != nil {
			return true, err
		}
	}
	return true, nil
}

// readHBA returns the managed lines of the jail's pg_hba.conf.
func (s *Service) readHBA(ctx context.Context, key, file string) ([]string, error) {
	b, err := s.d.Files.ReadFile(ctx, s.rootMount(key)+file)
	if err != nil {
		return nil, err
	}
	lines, _, err := apps.HBABlock(string(b))
	return lines, err
}

// AllowApp answers POST /api/v1/jails/<name>/access.
func (s *Service) AllowApp(ctx context.Context, name string, req api.AppAllow) (api.AppAllowResult, error) {
	if err := s.requireHost("apps"); err != nil {
		return api.AppAllowResult{}, err
	}
	t, err := s.appTarget(ctx, name)
	if err != nil {
		return api.AppAllowResult{}, err
	}
	s.accMu.Lock()
	defer s.accMu.Unlock()
	unlock, err := s.locks.lockPatient(ctx, "allow access to "+name, jailLock(t.key))
	if err != nil {
		return api.AppAllowResult{}, err
	}
	defer unlock()
	// read again under the lock
	if t, err = s.appTarget(ctx, name); err != nil {
		return api.AppAllowResult{}, err
	}
	src, err := apps.ParseSource(req.Source)
	if err != nil {
		return api.AppAllowResult{}, invalid("%v", err)
	}
	rs, err := s.resolveSource(ctx, t, src)
	if err != nil {
		return api.AppAllowResult{}, err
	}
	proj, jail := t.p.Meta.Name, t.jail.Metadata.Name
	res := api.AppAllowResult{Jail: jail, DryRun: req.DryRun}
	portsIn := req.Ports
	if len(portsIn) == 0 && t.def != nil {
		portsIn = apps.DefaultPorts(*t.def)
	}
	if len(portsIn) == 0 {
		return res, invalid("app %s declares no ports; name one with --port N[/tcp|udp]", t.app)
	}
	ports, err := apps.ParsePorts(portsIn)
	if err != nil {
		return res, invalid("%v", err)
	}
	acc := t.access()
	i := findGrant(t.rec.Grants, rs.canonical)
	now := s.now().UTC()
	g := accessGrant{Source: rs.canonical, Kind: rs.kind, SourceName: rs.name, From: rs.from,
		CreatedAt: now, CreatedBy: ActorFrom(ctx).Name}
	for _, p := range ports {
		g.Ports = append(g.Ports, p.String())
	}
	for _, p := range rs.prefixes {
		g.Prefixes = append(g.Prefixes, p.String())
	}
	if i >= 0 {
		old := t.rec.Grants[i]
		g.CreatedAt, g.CreatedBy, g.Database = old.CreatedAt, old.CreatedBy, old.Database
	}
	appAddrs := jailAddrs(s.effective(t.jail))
	rec := t.rec
	if !t.has {
		rec = accessRecord{}
	}
	has := t.has // the registry object exists (it is saved once psql made a role)
	var st []apps.Statement
	var password string
	needRestart := false
	var listen string
	if acc != nil {
		if rec.Type == "" {
			rec.Type, rec.HBAFile, rec.Service, rec.Port = acc.Type, acc.HBAFile, acc.Service, t.dbPort()
		}
		db := req.Database
		if db == "" {
			db = g.Database
		}
		if db == "" && rs.kind == api.AccessSourceJail {
			db = apps.DefaultDatabase(rs.name)
		}
		if db == "" {
			return res, invalid("name the database of this grant with --db NAME (a source that is not a jail has no default)")
		}
		if err := apps.CheckDatabaseName(db); err != nil {
			return res, invalid("%v", err)
		}
		if g.Database != "" && g.Database != db {
			return res, api.Errorf(api.CodeConflict, "%s already has access to database %s", rs.canonical, g.Database).
				WithHint("deny it first to give it another database")
		}
		g.Database = db
		g.HBA = apps.HBALines(db, db, rs.prefixes)
		if !s.jailRunning(ctx, t.key) {
			return res, api.Errorf(api.CodeBusy, "jail %q is stopped; the role and the database are made with psql in it", jail).
				WithHint("start it with jailops start " + jail)
		}
		probe, err := s.psql(ctx, t.key, "postgres", []apps.Statement{{SQL: apps.ProbeSQL(db, db)}})
		if err != nil {
			return res, err
		}
		pr, err := apps.ParseProbe(probe)
		if err != nil {
			return res, err
		}
		role, ri := rec.role(db)
		switch {
		case pr.Role && ri < 0:
			return res, api.Errorf(api.CodeConflict, "role %q exists in the database server and was not made by JailOps", db).
				WithHint("JailOps never changes a role it did not make: choose another name with --db")
		case !pr.Role || !role.Login || role.Unfinished || req.Rotate:
			if password, err = apps.NewPassword(accessRand); err != nil {
				return res, internal(err)
			}
			salt := make([]byte, 16)
			if _, err := io.ReadFull(accessRand, salt); err != nil {
				return res, internal(err)
			}
			v, err := apps.ScramVerifier(password, salt, apps.ScramIterations)
			if err != nil {
				return res, internal(err)
			}
			if pr.Role {
				st = append(st, apps.SetPassword(db, v))
			} else {
				st = append(st, apps.CreateRole(db, v))
			}
		}
		switch {
		case pr.Database && !role.DatabaseCreated:
			return res, api.Errorf(api.CodeConflict, "database %q exists and was not made by JailOps", db).
				WithHint("choose another name with --db")
		case !pr.Database:
			st = append(st, apps.CreateDatabase(db, db))
		case !pr.Role:
			// the role was dropped and the database kept: give it back
			st = append(st, apps.OwnDatabase(db, db))
		}
		var changed bool
		if listen, changed = apps.ListenValue(pr.Listen, appAddrs); changed {
			st = append(st, apps.SetListen(listen))
			needRestart = true
		}
		res.SQL = apps.Shown(st)
	}
	// what the firewall gets
	rules := grantRules(g)
	var drop []string
	if i >= 0 {
		drop = ruleNames(grantRules(t.rec.Grants[i]))
	}
	_, polOK, err := s.accessPolicy(proj, jail)
	if err != nil {
		return res, err
	}
	for _, r := range rules {
		res.Grant.Rules = append(res.Grant.Rules, apps.RuleText(r))
	}
	res.Steps = append(res.Steps, fmt.Sprintf("firewall policy %s: %s", apps.AccessPolicyName(jail), strings.Join(res.Grant.Rules, "; ")))
	if !polOK {
		res.Notes = append(res.Notes, "jail "+jail+" was open to its network until now (installed before app access); from now on it is closed to every source that is not allowed")
	}
	if len(st) > 0 {
		res.Steps = append(res.Steps, "in the jail, as postgres: psql with the statements on standard input")
	}
	if needRestart {
		res.Steps = append(res.Steps, fmt.Sprintf("listen_addresses becomes %q: restart %s in the jail", listen, rec.Service))
	}
	if len(g.HBA) > 0 {
		res.Steps = append(res.Steps, fmt.Sprintf("%s: the managed block gets %s; then the server reloads it", rec.HBAFile, strings.Join(g.HBA, "; ")))
	}
	if acc == nil {
		res.Notes = append(res.Notes, appOnlyFirewallNote(t.app))
	}
	if ps := rs.prefixes; len(ps) > 0 {
		for _, p := range ps {
			if p.Bits() == 0 {
				res.Notes = append(res.Notes, "this source is every address: anything that reaches the jail's network may connect")
				break
			}
		}
	}
	if req.DryRun {
		res.Grant = s.grantToAPI(g, rec, nil)
		res.Grant.Rules = nil
		for _, r := range rules {
			res.Grant.Rules = append(res.Grant.Rules, apps.RuleText(r))
		}
		res.Changed = true
		return res, nil
	}

	// apply: the database first (nothing reaches it before its line is in), then the file, then the firewall
	changed := false
	if acc != nil {
		db := g.Database
		if len(st) > 0 {
			var main, listenSt []apps.Statement
			for _, x := range st {
				if strings.HasPrefix(x.SQL, "ALTER SYSTEM") {
					listenSt = append(listenSt, x)
				} else {
					main = append(main, x)
				}
			}
			if len(main) > 0 {
				if _, err := s.psql(ctx, t.key, "postgres", main); err != nil {
					return res, err
				}
				role, ri := rec.role(db)
				created := slices.ContainsFunc(main, func(x apps.Statement) bool { return strings.HasPrefix(x.SQL, "CREATE DATABASE") })
				if ri < 0 {
					rec.Roles = append(rec.Roles, accessRole{Name: db, DatabaseCreated: created, Login: true, Unfinished: password != ""})
				} else {
					role.Login, role.DatabaseCreated = true, role.DatabaseCreated || created
					role.Unfinished = role.Unfinished || password != ""
					rec.Roles[ri] = role
				}
				changed = true
				// the registry knows the role before anything else can fail: a retry finds it as JailOps's own
				if err := s.saveAccess(ctx, proj, jail, has, rec); err != nil {
					return res, err
				}
				has = true
			}
			if len(listenSt) > 0 {
				if _, err := s.psql(ctx, t.key, "postgres", listenSt); err != nil {
					return res, err
				}
				changed = true
			}
		}
		// the record of the grant goes in first: the file is rendered from it
		next := slices.Clone(rec.Grants)
		if i >= 0 {
			next[i] = g
		} else {
			next = append(next, g)
		}
		wrote, err := s.writeHBA(ctx, t.key, rec.HBAFile, hbaLines(next))
		if err != nil {
			return res, err
		}
		changed = changed || wrote
		if needRestart {
			argv, err := apps.ServiceRestartArgv(rec.Service)
			if err != nil {
				return res, err
			}
			if _, err := s.runInJail(ctx, t.key, 10*time.Minute, argv...); err != nil {
				return res, fmt.Errorf("/usr/sbin/service %s restart: %w", rec.Service, errors.Unwrap(err))
			}
		} else if wrote {
			if _, err := s.psql(ctx, t.key, "postgres", []apps.Statement{apps.Reload()}); err != nil {
				return res, err
			}
		}
		if password != "" {
			host := appAddrs[0]
			for _, a := range appAddrs {
				if a.Is4() {
					host = a
					break
				}
			}
			res.ConnectionString = apps.ConnectionString(db, password, host, t.dbPort(), db)
			res.Notes = append(res.Notes, "the connection string is shown once and stored nowhere; jailops app allow "+jail+" --from "+rs.canonical+" --rotate makes a new password")
		} else {
			res.Notes = append(res.Notes, "role "+db+" exists: its password was shown when it was made; --rotate makes a new one")
		}
	}
	pc, err := s.writeAccessPolicy(ctx, proj, jail, drop, rules, false)
	if err != nil {
		return res, err
	}
	changed = changed || pc
	if i >= 0 && !grantEqual(t.rec.Grants[i], g) {
		changed = true
	}
	if i < 0 {
		changed = true
	}
	if changed {
		if i >= 0 {
			g.UpdatedAt = now
			rec.Grants[i] = g
		} else {
			rec.Grants = append(rec.Grants, g)
		}
		if _, ri := rec.role(g.Database); ri >= 0 {
			rec.Roles[ri].Unfinished = false // the password is in this answer
		}
		if err := s.saveAccess(ctx, proj, jail, has, rec); err != nil {
			return res, err
		}
	} else {
		g = t.rec.Grants[i]
		res.Notes = append(res.Notes, "nothing changed: the grant exists as it is")
	}
	res.Changed = changed
	res.Grant = s.grantToAPI(g, rec, nil)
	return res, nil
}

func grantEqual(a, b accessGrant) bool {
	a.CreatedAt, a.UpdatedAt, a.CreatedBy = time.Time{}, time.Time{}, ""
	b.CreatedAt, b.UpdatedAt, b.CreatedBy = time.Time{}, time.Time{}, ""
	return jsonEq(a, b)
}

// appOnlyFirewallNote says what an app without an access block needs on its
// own side.
func appOnlyFirewallNote(app string) string {
	n := "only the firewall changed: the app must itself listen on the jail's address and accept the client (see its configuration files with jailops app info " + app + ")"
	if app == "valkey" {
		n += "; Valkey binds 127.0.0.1 with protected-mode yes until bind and protected-mode in /usr/local/etc/valkey.conf are changed, and requirepass should be set before it is reachable"
	}
	return n
}

func (s *Service) saveAccess(ctx context.Context, project, jail string, exists bool, rec accessRecord) error {
	ks := s.accKind().p(project)
	if !exists {
		_, err := ks.create(ctx, api.ObjectMeta{Name: jail}, rec)
		return err
	}
	if len(rec.Grants) == 0 && len(rec.Roles) == 0 {
		return ks.delete(ctx, jail, AnyGeneration)
	}
	_, err := ks.update(ctx, jail, AnyGeneration, nil, nil, rec)
	return err
}

// DenyApp answers POST /api/v1/jails/<name>/access/deny.
func (s *Service) DenyApp(ctx context.Context, name string, req api.AppDeny) (api.AppDenyResult, error) {
	if err := s.requireHost("apps"); err != nil {
		return api.AppDenyResult{}, err
	}
	t, err := s.appTarget(ctx, name)
	if err != nil {
		return api.AppDenyResult{}, err
	}
	s.accMu.Lock()
	defer s.accMu.Unlock()
	unlock, err := s.locks.lockPatient(ctx, "deny access to "+name, jailLock(t.key))
	if err != nil {
		return api.AppDenyResult{}, err
	}
	defer unlock()
	if t, err = s.appTarget(ctx, name); err != nil {
		return api.AppDenyResult{}, err
	}
	src, err := apps.ParseSource(req.Source)
	if err != nil {
		return api.AppDenyResult{}, invalid("%v", err)
	}
	proj, jail := t.p.Meta.Name, t.jail.Metadata.Name
	res := api.AppDenyResult{Jail: jail, DryRun: req.DryRun}
	canonical := src.Canonical()
	i := findGrant(t.rec.Grants, canonical)
	if i < 0 {
		res.Notes = append(res.Notes, "nothing changed: "+canonical+" has no access to "+jail)
		return res, nil
	}
	g := t.rec.Grants[i]
	rec := t.rec
	rest := slices.Delete(slices.Clone(rec.Grants), i, i+1)
	res.Removed = s.grantToAPI(g, rec, nil)
	var main, inDB []apps.Statement
	if g.Database != "" {
		role, ri := rec.role(g.Database)
		used := slices.ContainsFunc(rest, func(o accessGrant) bool { return o.Database == g.Database })
		switch {
		case used:
			res.Notes = append(res.Notes, "role "+g.Database+" stays: another grant uses it")
		case ri < 0:
			res.Notes = append(res.Notes, "role "+g.Database+" was not made by JailOps and is left as it is")
		case req.DropRole:
			inDB = apps.ReassignOwned(g.Database)
			main = append(apps.DisableRole(g.Database), apps.DropRole(g.Database))
			res.Notes = append(res.Notes, "role "+g.Database+" is dropped; what it owned now belongs to postgres and database "+g.Database+" is kept")
		case role.Login:
			main = apps.DisableRole(g.Database)
			res.Notes = append(res.Notes, "role "+g.Database+" keeps its database and loses its login and password; --drop-role drops it")
		}
		res.SQL = append(apps.Shown(inDB), apps.Shown(main)...)
		if !req.DryRun && !s.jailRunning(ctx, t.key) {
			return res, api.Errorf(api.CodeBusy, "jail %q is stopped; the role and %s are changed with psql in it", jail, rec.HBAFile).
				WithHint("start it with jailops start " + jail)
		}
		res.Steps = append(res.Steps, fmt.Sprintf("%s: the managed block loses %s; then the server reloads it", rec.HBAFile, strings.Join(g.HBA, "; ")))
	}
	for _, r := range grantRules(g) {
		res.Steps = append(res.Steps, "firewall policy "+apps.AccessPolicyName(jail)+": remove "+apps.RuleText(r))
	}
	res.Changed = true
	if req.DryRun {
		return res, nil
	}
	// the firewall first: nothing gets in from the moment of the deny on
	if _, err := s.writeAccessPolicy(ctx, proj, jail, ruleNames(grantRules(g)), nil, false); err != nil {
		return res, err
	}
	if g.Database != "" {
		wrote, err := s.writeHBA(ctx, t.key, rec.HBAFile, hbaLines(rest))
		if err != nil {
			return res, err
		}
		if wrote {
			if _, err := s.psql(ctx, t.key, "postgres", []apps.Statement{apps.Reload()}); err != nil {
				return res, err
			}
		}
		if len(inDB) > 0 {
			if _, err := s.psql(ctx, t.key, g.Database, inDB); err != nil {
				return res, err
			}
		}
		if len(main) > 0 {
			if _, err := s.psql(ctx, t.key, "postgres", main); err != nil {
				return res, err
			}
		}
		if _, ri := rec.role(g.Database); ri >= 0 && len(main) > 0 {
			// a dropped role stays in the registry without login: the database it was given is still one
			// JailOps made, and a later allow with the same name makes the role again and gives it back
			rec.Roles[ri].Login = false
		}
	}
	rec.Grants = rest
	if err := s.saveAccess(ctx, proj, jail, true, rec); err != nil {
		return res, err
	}
	return res, nil
}

// grantToAPI is a grant as the API shows it; pf are the rendered lines of
// the jail's anchor, when known.
func (s *Service) grantToAPI(g accessGrant, rec accessRecord, pf []string) api.AppAccessGrant {
	out := api.AppAccessGrant{Source: g.Source, SourceKind: g.Kind, Addresses: g.Prefixes,
		Ports: g.Ports, Database: g.Database, Role: g.Database, HBA: g.HBA, CreatedAt: g.CreatedAt, UpdatedAt: g.UpdatedAt,
		CreatedBy: g.CreatedBy, PF: pf}
	if out.Ports == nil {
		out.Ports = []string{}
	}
	if g.Database != "" {
		if r, i := rec.role(g.Database); i >= 0 {
			out.RoleCreated, out.DatabaseCreated = true, r.DatabaseCreated
		}
	}
	for _, r := range grantRules(g) {
		out.Rules = append(out.Rules, apps.RuleText(r))
	}
	if out.Rules == nil {
		out.Rules = []string{}
	}
	return out
}

// GetAppAccess answers GET /api/v1/jails/<name>/access: the grants, the rules
// and lines they generated, and what of that is missing on the host.
func (s *Service) GetAppAccess(ctx context.Context, name string) (api.AppAccess, error) {
	if err := s.requireHost("apps"); err != nil {
		return api.AppAccess{}, err
	}
	t, err := s.appTarget(ctx, name)
	if err != nil {
		return api.AppAccess{}, err
	}
	return s.appAccess(ctx, t), nil
}

func (s *Service) appAccess(ctx context.Context, t appTarget) api.AppAccess {
	proj, jail := t.p.Meta.Name, t.jail.Metadata.Name
	out := api.AppAccess{Jail: jail, Project: proj, App: t.app, Policy: apps.AccessPolicyName(jail), Grants: []api.AppAccessGrant{}, Ports: []string{}}
	if acc := t.access(); acc != nil {
		out.Type = acc.Type
	}
	if t.def != nil {
		if p := apps.DefaultPorts(*t.def); p != nil {
			out.Ports = p
		}
	}
	pol, ok, err := s.accessPolicy(proj, jail)
	switch {
	case err != nil:
		out.Warnings = append(out.Warnings, err.Error())
	case !ok:
		out.Warnings = append(out.Warnings, "the jail is open to its network: it was installed before app access, and its first allow closes it to every other source")
	default:
		out.Closed = pol.Spec.DefaultIn == "deny"
	}
	running := s.jailRunning(ctx, t.key)
	if !running {
		out.Warnings = append(out.Warnings, "the jail is stopped: its anchor is not loaded and pg_hba.conf is not checked")
	}
	// the rendered anchor, for the lines each rule became
	anchor := ""
	if sets, err := s.allRefs(proj); err == nil {
		if b, err := s.buildJail(ctx, t.jail, sets); err == nil {
			anchor = b.desired.Ruleset
		}
	}
	var hba []string
	hbaOK := false
	if t.rec.HBAFile != "" && running {
		if l, err := s.readHBA(ctx, t.key, t.rec.HBAFile); err == nil {
			hba, hbaOK = l, true
		} else {
			out.Warnings = append(out.Warnings, fmt.Sprintf("%s cannot be read: %v", t.rec.HBAFile, err))
		}
	}
	for _, g := range t.rec.Grants {
		var pf []string
		for _, r := range grantRules(g) {
			pf = append(pf, anchorLines(anchor, r.Name)...)
		}
		ag := s.grantToAPI(g, t.rec, pf)
		ag.Problems = s.grantProblems(proj, jail, g, pol, ok, hba, hbaOK)
		out.Grants = append(out.Grants, ag)
	}
	return out
}

// grantProblems compares a grant with the policy and the file. The firewall rule of @web or @office follows the jail
// or the set at every render; the lines of pg_hba.conf are a copy made when the grant was, so a change of the
// addresses is reported here and repeating the allow refreshes the lines.
func (s *Service) grantProblems(project, jail string, g accessGrant, pol object[api.FirewallPolicySpec], polOK bool, hba []string, hbaOK bool) []string {
	var out []string
	if g.Database != "" && (g.Kind == api.AccessSourceJail || g.Kind == api.AccessSourceSet) {
		var now []netip.Prefix
		var err error
		if g.Kind == api.AccessSourceJail {
			now, err = s.jailPrefixes(project, g.SourceName)
		} else {
			now, err = s.setPrefixes(project, g.SourceName)
		}
		if err == nil && !samePrefixes(now, g.Prefixes) {
			out = append(out, fmt.Sprintf("the addresses of %s are now %s but the pg_hba lines name %s: repeat jailops app allow %s --from %s to refresh them",
				g.Source, prefixList(now), strings.Join(g.Prefixes, ", "), jail, g.Source))
		}
	}
	for _, r := range grantRules(g) {
		if !polOK || !slices.ContainsFunc(pol.Spec.Rules, func(x api.FirewallRule) bool { return jsonEq(x, r) }) {
			out = append(out, "firewall rule missing from policy "+pol.Meta.Name+": "+apps.RuleText(r))
		}
	}
	if hbaOK {
		for _, l := range g.HBA {
			if !slices.Contains(hba, l) {
				out = append(out, "pg_hba line missing: "+l)
			}
		}
	}
	return out
}

// anchorLines are the rule lines of a named rule in a rendered anchor, with
// the state labels left out.
func anchorLines(anchor, rule string) []string {
	var out []string
	in := false
	for _, l := range strings.Split(anchor, "\n") {
		if strings.HasPrefix(l, "#") {
			_, name, ok := strings.Cut(l, ": ")
			in = ok && strings.HasPrefix(l, "# rule ") && name == rule
			continue
		}
		if !in || strings.TrimSpace(l) == "" || strings.HasPrefix(l, "table ") {
			in = false
			continue
		}
		if i := strings.Index(l, ` label "`); i > 0 {
			l = l[:i]
		}
		out = append(out, l)
	}
	return out
}

// accessDrift lists the problems of every grant of every app on the host,
// for doctor: "project/jail: problem".
func (s *Service) accessDrift(ctx context.Context) ([]string, int, error) {
	objs, err := s.accKind().listAll()
	if err != nil {
		return nil, 0, err
	}
	var out []string
	n := 0
	for _, o := range objs {
		key, err := validate.QualifiedName(o.Meta.Project, o.Meta.Name)
		if err != nil {
			continue
		}
		j, err := s.jailSnapshot(key)
		if err != nil {
			continue
		}
		pol, ok, _ := s.accessPolicy(o.Meta.Project, o.Meta.Name)
		var hba []string
		hbaOK := false
		if o.Spec.HBAFile != "" && s.jailRunning(ctx, key) {
			if l, err := s.readHBA(ctx, key, o.Spec.HBAFile); err == nil {
				hba, hbaOK = l, true
			}
		}
		_ = j
		for _, g := range o.Spec.Grants {
			n++
			for _, p := range s.grantProblems(o.Meta.Project, o.Meta.Name, g, pol, ok, hba, hbaOK) {
				out = append(out, o.Meta.Project+"/"+o.Meta.Name+" "+g.Source+": "+p)
			}
		}
	}
	return out, n, nil
}

// accessJailGone cleans up after a jail was deleted: its own managed policy
// and registry go. A jail that a grant names as its source is not deleted
// (noRuleNamesJail), so no grant is left naming a jail that is gone.
func (s *Service) accessJailGone(ctx context.Context, project, jail string) {
	if _, ok, err := s.accessPolicy(project, jail); err == nil && ok {
		if err := s.polKind.p(project).delete(ctx, apps.AccessPolicyName(jail), AnyGeneration); err != nil {
			s.log.Warn("app access: removing the policy of a deleted jail failed", "project", project, "jail", jail, "err", err)
		}
	}
	if s.accKind().p(project).exists(jail) {
		if err := s.accKind().p(project).delete(ctx, jail, AnyGeneration); err != nil {
			s.log.Warn("app access: removing the grants of a deleted jail failed", "project", project, "jail", jail, "err", err)
		}
	}
	s.kick()
}

// accessRulesFor returns the managed policy of a jail for the renderer: its
// rules come after the project's mandatory policy and before the jail's own,
// and closed says it denies inbound traffic by default.
func (s *Service) accessRulesFor(project, jail string) (rules []api.FirewallRule, closed bool) {
	pol, ok, err := s.accessPolicy(project, jail)
	if err != nil || !ok {
		return nil, false
	}
	return pol.Spec.Rules, pol.Spec.DefaultIn == "deny"
}

// samePrefixes says whether a list of prefixes is the list of strings, in any order.
func samePrefixes(now []netip.Prefix, then []string) bool {
	a := make([]string, 0, len(now))
	for _, p := range now {
		a = append(a, p.String())
	}
	b := slices.Clone(then)
	sort.Strings(a)
	sort.Strings(b)
	return slices.Equal(a, b)
}

func prefixList(ps []netip.Prefix) string {
	var out []string
	for _, p := range ps {
		out = append(out, p.String())
	}
	sort.Strings(out)
	return strings.Join(out, ", ")
}
