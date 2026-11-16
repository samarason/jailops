// Command gen-ts writes web/shared/src/api/types.gen.ts from the exported wire types of
// jailops.net/jailops/sdk/api. It uses reflect and the standard library only.
//
//	go run ./scripts/gen-ts          write the file
//	go run ./scripts/gen-ts -check   exit 1 when the file is stale
//
// reflect cannot list a package's types or constants, so the roots and the enum values are
// tables below. A root is walked recursively: every struct reachable from it is emitted. A new
// wire type that is reachable from a root needs no change; a new root or enum constant does.
package main

import (
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"time"

	"jailops.net/jailops/sdk/api"
)

const defaultOut = "web/shared/src/api/types.gen.ts"

// roots are the types the UI uses directly. Everything they reference is emitted too.
var roots = []any{
	api.ServerInfo{}, api.Response{}, api.Operation{}, api.Event{}, api.LifecycleEvent{}, api.Error{},
	api.Jail{}, api.JailAction{}, api.JailRollback{}, api.JailUpgrade{}, api.JailSnapshot{}, api.JailUsage{}, api.JailLogFile{}, api.JailLogRead{},
	api.Image{}, api.ImageBuild{}, api.ImageUpgrade{}, api.ImageUpgradeResult{}, api.ImageAliasSet{},
	api.Network{}, api.Lease{},
	api.WireGuard{}, api.WireGuardPeerAdd{}, api.WireGuardPeerCreated{}, api.WireGuardJoin{}, api.WireGuardKeys{},
	api.FirewallPolicy{}, api.AddressSet{}, api.Volume{}, api.VolumeCreate{}, api.VolumeUnlock{}, api.VolumePassphraseChange{}, api.VolumeRollback{}, api.VolumeAttachRequest{}, api.VolumeSnapshot{}, api.FirewallTestRequest{}, api.FirewallTestResult{},
	api.BackupTarget{}, api.BackupPolicy{}, api.Backup{}, api.RestoreRequest{}, api.RestorePreflight{},
	api.Token{}, api.Certificate{}, api.User{}, api.Remote{},
	api.Document{},
	api.Project{}, api.ProjectAggregate{}, api.ProjectHostStatus{}, api.Storage{}, api.Session{}, api.Identity{}, api.TrustTokenRequest{}, api.TrustToken{}, api.TrustClientRequest{}, api.Profile{}, api.ConfigKey{}, api.JailExpanded{}, api.ConfigChange{}, api.UpdateReport{}, api.UpdateRecord{}, api.UpdateCheckRequest{}, api.UpdateApplyRequest{},
	api.Provision{}, api.ProvisionRequest{}, api.ProvisionResult{}, api.ShellSetupRequest{}, api.ShellSetupResult{}, api.ExecRequest{}, api.BackupRun{}, api.BackupRunRequest{}, api.BackupVerifyRequest{},
	api.BackupKeyStatus{}, api.BackupKeyCreate{}, api.BackupKeyCreated{}, api.BackupKeyEscrow{},
	api.AuditEntry{}, api.PoolUsage{}, api.DoctorReport{}, api.RepositoryStatus{}, api.UserCreate{}, api.UserCreated{}, api.PasswordSet{},
	api.AppSummary{}, api.AppDetail{}, api.AppInstall{}, api.AppInstallResult{}, api.AppDraft{},
	api.HostIdentity{}, api.HostIdentityApply{}, api.HostRestore{}, api.HostChange{}, api.HostSnapshot{},
	api.HostFirewall{}, api.HostFirewallApply{}, api.HostPending{}, api.HostPendingAction{},
	api.AppAccess{}, api.AppAllow{}, api.AppAllowResult{}, api.AppDeny{}, api.AppDenyResult{},
	api.LogsRead{}, api.LogForward{}, api.LogForwardTest{}, api.LogForwardTestResult{},
	api.HostCertificate{}, api.HostCertificateUpload{}, api.ACMESpec{},
	api.SetupStatus{}, api.SetupRequest{}, api.SetupResult{}, api.SetupToken{},
	api.Rename{}, api.RenameResult{},
}

// enums lists the typed string constants. Keep in sync with sdk/api.
var enums = map[reflect.Type][]string{
	reflect.TypeFor[api.Code]():            {"invalid", "not_found", "already_exists", "conflict", "unauthorized", "forbidden", "unsupported", "busy", "internal", "ip_conflict", "pool_exhausted", "image_in_use", "data_loss_unconfirmed", "version_skew", "not_leader", "no_quorum", "unverified_platform", "zfs_incompatible", "chain_broken", "merge_conflict", "quota_exceeded", "rate_limited", "key_not_escrowed", "plaintext_denied", "maintenance", "missing_chunks", "lease_expired", "not_managed", "locked", "bad_passphrase", "stop_forced"},
	reflect.TypeFor[api.Permission]():      {string(api.PermReadonly), string(api.PermOperator), string(api.PermAdmin), string(api.PermBackupPush), string(api.PermBackupPull), string(api.PermRestore), string(api.PermBackupAdmin)},
	reflect.TypeFor[api.Role]():            {string(api.RoleHost), string(api.RoleBackup)},
	reflect.TypeFor[api.OS]():              {string(api.OSFreeBSD), string(api.OSLinux)},
	reflect.TypeFor[api.Layout]():          {string(api.LayoutThin), string(api.LayoutThick)},
	reflect.TypeFor[api.UpdateStrategy]():  {string(api.UpdateRebase), string(api.UpdateInPlace), string(api.UpdateManual)},
	reflect.TypeFor[api.DNSSource]():       {string(api.DNSFromNetwork), string(api.DNSFromHost), string(api.DNSFromGateway), string(api.DNSNone)},
	reflect.TypeFor[api.PowerState]():      {string(api.PowerStopped), string(api.PowerStarting), string(api.PowerRunning), string(api.PowerStopping), string(api.PowerError), string(api.PowerLocked)},
	reflect.TypeFor[api.RollbackScope]():   {string(api.RollbackRoot), string(api.RollbackData), string(api.RollbackAll)},
	reflect.TypeFor[api.IPv6Mode]():        {string(api.IPv6Routed), string(api.IPv6Proxy), string(api.IPv6None)},
	reflect.TypeFor[api.WireGuardMode]():   {string(api.WireGuardServer), string(api.WireGuardClient)},
	reflect.TypeFor[api.ResponseType]():    {string(api.ResponseSync), string(api.ResponseAsync), string(api.ResponseError)},
	reflect.TypeFor[api.OperationStatus](): {string(api.OpPending), string(api.OpRunning), string(api.OpSuccess), string(api.OpFailure), string(api.OpCancelled)},
	reflect.TypeFor[api.EventType]():       {string(api.EventLifecycle), string(api.EventOperation), string(api.EventLogging)},
	reflect.TypeFor[api.Kind]():            {string(api.KindJail), string(api.KindImage), string(api.KindNetwork), string(api.KindFirewallPolicy), string(api.KindAddressSet), string(api.KindBackupPolicy), string(api.KindBackupTarget), string(api.KindHostGroup), string(api.KindRollout), string(api.KindJailTemplate), string(api.KindRemote), string(api.KindUser), string(api.KindToken), string(api.KindCertificate), string(api.KindHost), string(api.KindImageGeneration), string(api.KindJailSnapshot), string(api.KindBackup), string(api.KindOperation), "Project", "Storage", string(api.KindHostIdentity), string(api.KindWireGuard), string(api.KindVolume), string(api.KindLogForward), string(api.KindHostFirewall), string(api.KindHostCertificate)},
	reflect.TypeFor[api.UpdateMode]():      {string(api.UpdateModeManual), string(api.UpdateModeNotify), string(api.UpdateModeManaged)},
	reflect.TypeFor[api.UpdateReboot]():    {string(api.RebootManual), string(api.RebootAuto)},
	reflect.TypeFor[api.DoctorStatus]():    {string(api.DoctorOK), string(api.DoctorWarn), string(api.DoctorFail), string(api.DoctorUnknown), string(api.DoctorInfo)},
	reflect.TypeFor[api.Scope]():           {string(api.ScopeHost), string(api.ScopeFleet)},
	reflect.TypeFor[api.JailLogKind]():     {string(api.JailLogActive), string(api.JailLogRotated)},
	reflect.TypeFor[api.AppCategory]():     {string(api.AppDatabase), string(api.AppWeb), string(api.AppTools), string(api.AppDevops), string(api.AppStorage), string(api.AppMonitoring), string(api.AppCommunication), string(api.AppNetwork), string(api.AppSecurity), string(api.AppOther)},
	reflect.TypeFor[api.AppSource]():       {string(api.AppSourceCatalog), string(api.AppSourceLocal)},
	reflect.TypeFor[api.LogSinkType]():     {string(api.LogSinkSyslog), string(api.LogSinkWebhook)},

	// the certificate of the console (host_certificate)
	reflect.TypeFor[api.CertificateSource](): {string(api.CertSourceSelfSigned), string(api.CertSourceConfigured), string(api.CertSourceUploaded), string(api.CertSourceACME)},
	reflect.TypeFor[api.ACMEChallenge]():     {string(api.ACMEHTTP01), string(api.ACMETLSALPN01)},
}

type gen struct {
	structs map[string]reflect.Type
	enumSet map[string]reflect.Type
}

func main() {
	check := flag.Bool("check", false, "fail when the generated file differs from the file on disk")
	out := flag.String("o", defaultOut, "output path, relative to the module root")
	flag.Parse()

	root, err := moduleRoot()
	if err != nil {
		fatal(err)
	}
	path := filepath.Join(root, *out)
	data, err := render()
	if err != nil {
		fatal(err)
	}
	if *check {
		cur, err := os.ReadFile(path)
		if err != nil || !bytes.Equal(cur, data) {
			fmt.Fprintf(os.Stderr, "%s is stale: run `go run ./scripts/gen-ts`\n", *out)
			os.Exit(1)
		}
		return
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		fatal(err)
	}
	if err := os.WriteFile(path, data, 0o644); err != nil {
		fatal(err)
	}
}

func fatal(err error) { fmt.Fprintln(os.Stderr, "gen-ts:", err); os.Exit(2) }

// moduleRoot walks up from the working directory to the directory holding go.mod and scripts/gen-ts.
func moduleRoot() (string, error) {
	dir, err := os.Getwd()
	if err != nil {
		return "", err
	}
	for {
		if _, err := os.Stat(filepath.Join(dir, "scripts", "gen-ts", "main.go")); err == nil {
			return dir, nil
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			return "", fmt.Errorf("run from inside the jailops repository")
		}
		dir = parent
	}
}

func render() ([]byte, error) {
	g := &gen{structs: map[string]reflect.Type{}, enumSet: map[string]reflect.Type{}}
	for _, r := range roots {
		if err := g.walk(reflect.TypeOf(r)); err != nil {
			return nil, err
		}
	}
	for t := range enums { // every listed enum is emitted, even when no root reaches it
		g.enumSet[t.Name()] = t
	}
	var b bytes.Buffer
	b.WriteString("// Code generated by scripts/gen-ts from sdk/api. DO NOT EDIT.\n")
	b.WriteString("// Fields with omitempty or omitzero are optional. Go encodes a nil slice or map without\n")
	b.WriteString("// omitempty as null: the API client normalises those to empty values.\n\n")

	names := sortedKeys(g.enumSet)
	for _, n := range names {
		t := g.enumSet[n]
		vals := enums[t]
		fmt.Fprintf(&b, "export type %s =", n)
		for _, v := range vals {
			fmt.Fprintf(&b, "\n  | %q", v)
		}
		b.WriteString("\n\n")
		fmt.Fprintf(&b, "export const %sValues: readonly %s[] = %s\n\n", n, n, jsonList(vals))
	}
	for _, n := range sortedKeys(g.structs) {
		t := g.structs[n]
		fmt.Fprintf(&b, "export interface %s {\n", n)
		for i := 0; i < t.NumField(); i++ {
			f := t.Field(i)
			if !f.IsExported() {
				continue
			}
			name, opt, skip := parseTag(f)
			if skip {
				continue
			}
			ts, nullable, err := g.tsType(f.Type)
			if err != nil {
				return nil, fmt.Errorf("%s.%s: %w", n, f.Name, err)
			}
			q := ""
			if opt {
				q = "?"
			} else if nullable {
				ts += " | null"
			}
			fmt.Fprintf(&b, "  %s%s: %s\n", name, q, ts)
		}
		b.WriteString("}\n\n")
	}
	b.WriteString("/** The config key registry of sdk/api (api.ConfigKeys): the console builds its editor from it. */\n")
	kb, err := json.MarshalIndent(api.ConfigKeys(), "", "  ")
	if err != nil {
		return nil, err
	}
	fmt.Fprintf(&b, "export const configKeys: readonly ConfigKey[] = %s\n\n", kb)
	fmt.Fprintf(&b, "export const apiVersion = %q\n", api.Version)
	fmt.Fprintf(&b, "/** Extensions of the API revision this UI was generated against. */\n")
	fmt.Fprintf(&b, "export const knownExtensions: readonly string[] = %s\n", jsonList(api.Extensions))
	return b.Bytes(), nil
}

func (g *gen) walk(t reflect.Type) error {
	for t.Kind() == reflect.Pointer || t.Kind() == reflect.Slice || t.Kind() == reflect.Array {
		t = t.Elem()
	}
	if t.Kind() == reflect.Map {
		return g.walk(t.Elem())
	}
	if t == reflect.TypeFor[time.Time]() || t == reflect.TypeFor[json.RawMessage]() {
		return nil
	}
	switch t.Kind() {
	case reflect.String:
		if _, ok := enums[t]; ok {
			g.enumSet[t.Name()] = t
		}
	case reflect.Struct:
		if t.PkgPath() == "" {
			return nil
		}
		if _, done := g.structs[t.Name()]; done {
			return nil
		}
		g.structs[t.Name()] = t
		for i := 0; i < t.NumField(); i++ {
			f := t.Field(i)
			if !f.IsExported() {
				continue
			}
			if _, _, skip := parseTag(f); skip {
				continue
			}
			if err := g.walk(f.Type); err != nil {
				return err
			}
		}
	}
	return nil
}

// tsType maps a Go type to TypeScript. nullable reports that Go may encode it as null.
func (g *gen) tsType(t reflect.Type) (ts string, nullable bool, err error) {
	switch {
	case t == reflect.TypeFor[time.Time]():
		return "string", false, nil // RFC 3339
	case t == reflect.TypeFor[json.RawMessage]():
		return "unknown", false, nil
	}
	switch t.Kind() {
	case reflect.Pointer:
		in, _, err := g.tsType(t.Elem())
		return in, true, err
	case reflect.Slice, reflect.Array:
		in, _, err := g.tsType(t.Elem())
		if strings.Contains(in, " | ") || strings.Contains(in, "=>") {
			in = "(" + in + ")"
		}
		return in + "[]", false, err
	case reflect.Map:
		if t.Key().Kind() != reflect.String {
			return "", false, fmt.Errorf("map key %s is not a string", t.Key())
		}
		in, _, err := g.tsType(t.Elem())
		return "Record<string, " + in + ">", false, err
	case reflect.Interface:
		return "unknown", false, nil
	case reflect.String:
		if _, ok := enums[t]; ok {
			return t.Name(), false, nil
		}
		return "string", false, nil
	case reflect.Bool:
		return "boolean", false, nil
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64,
		reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64, reflect.Float32, reflect.Float64:
		return "number", false, nil
	case reflect.Struct:
		return t.Name(), false, nil
	}
	return "", false, fmt.Errorf("unsupported kind %s", t.Kind())
}

// parseTag returns the JSON name, whether the field is optional, and whether it is skipped.
func parseTag(f reflect.StructField) (name string, optional, skip bool) {
	tag := f.Tag.Get("json")
	if tag == "-" {
		return "", false, true
	}
	parts := strings.Split(tag, ",")
	name = parts[0]
	if name == "" {
		name = f.Name
	}
	for _, p := range parts[1:] {
		if p == "omitempty" || p == "omitzero" {
			optional = true
		}
	}
	return name, optional, false
}

func jsonList(s []string) string {
	b, _ := json.Marshal(s)
	return strings.ReplaceAll(strings.ReplaceAll(string(b), `","`, `', '`), `"`, `'`)
}

func sortedKeys[V any](m map[string]V) []string {
	k := make([]string, 0, len(m))
	for n := range m {
		k = append(k, n)
	}
	sort.Strings(k)
	return k
}
