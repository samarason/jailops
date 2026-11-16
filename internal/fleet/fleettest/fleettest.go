// Package fleettest builds fleet repositories and in-memory hosts for tests.
// It is test support, shared by the tests of several packages; nothing else
// imports it.
package fleettest

import (
	"net/http/httptest"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"jailops.net/jailops/internal/fleet/secrets"
	"jailops.net/jailops/sdk/fake"
)

// Host is one in-memory host.
type Host struct {
	Name   string
	Server *fake.Server
	HTTP   *httptest.Server
	// Token is the API token the server requires, if any.
	Token string
}

// URL is the host's API address.
func (h *Host) URL() string { return h.HTTP.URL }

// Env is a temporary fleet repository with in-memory hosts.
type Env struct {
	T         *testing.T
	Dir       string
	State     string
	Hosts     map[string]*Host
	Identity  string // path of the age identity file (mode 0600)
	Recipient string

	std bool // StandardObjects was called: projects/main.yaml follows the host list
}

// Project is the project of the standard objects and of Env.Jail.
const Project = "main"

// writeMainProject (re)writes projects/main.yaml spanning every host added so far.
func (e *Env) writeMainProject() {
	var hosts []string // every host of the repository, including hosts reached through a hub
	ents, _ := os.ReadDir(filepath.Join(e.Dir, "hosts"))
	for _, d := range ents {
		if d.IsDir() {
			hosts = append(hosts, d.Name())
		}
	}
	sort.Strings(hosts)
	e.Write("projects/"+Project+".yaml", "apiVersion: jailops/v1\nkind: Project\nmetadata:\n  name: "+Project+"\nspec:\n  hosts: ["+strings.Join(hosts, ", ")+"]\n  networks: [{network: internal}]\n  storage: [{storage: default}]\n")
}

// New creates a repository with fleet.yaml, an age identity, secrets/recipients.txt
// and one host.yaml per name, each pointing at its own fake server. Hosts named
// in tokens require that API token (stored as secret "<host>-token").
func New(t *testing.T, id string, hosts ...string) *Env {
	t.Helper()
	e := &Env{T: t, Dir: t.TempDir(), State: t.TempDir(), Hosts: map[string]*Host{}}
	e.Write("fleet.yaml", "id: "+id+"\n")
	ident, err := secrets.GenerateIdentity()
	if err != nil {
		t.Fatal(err)
	}
	e.Recipient = ident.Recipient().String()
	e.Identity = filepath.Join(t.TempDir(), "identity.txt")
	if err := os.WriteFile(e.Identity, []byte(ident.String()+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	e.Write("secrets/recipients.txt", e.Recipient+"\n")
	for _, h := range hosts {
		e.AddHost(h, "")
	}
	return e
}

// AddHost starts a fake server and writes hosts/<name>/host.yaml. A non-empty
// token makes the server require it and the host use secret "<name>-token".
func (e *Env) AddHost(name, token string, opts ...fake.Option) *Host {
	e.T.Helper()
	if token != "" {
		opts = append(opts, fake.WithToken(token))
	}
	opts = append(opts, fake.WithHostName(name))
	srv := fake.New(opts...)
	ts := httptest.NewServer(srv)
	e.T.Cleanup(func() { ts.Close(); srv.Close() })
	h := &Host{Name: name, Server: srv, HTTP: ts, Token: token}
	e.Hosts[name] = h
	spec := "  url: " + ts.URL + "\n"
	if token != "" {
		e.WriteSecret(name+"-token", token)
		spec += "  token_secret: " + name + "-token\n"
	}
	e.Write("hosts/"+name+"/host.yaml", "apiVersion: jailops/v1\nkind: Host\nmetadata:\n  name: "+name+"\n  labels:\n    env: test\nspec:\n"+spec)
	if e.std {
		e.writeMainProject()
	}
	return h
}

// Write writes a file under the repository, creating directories.
func (e *Env) Write(rel, content string) {
	e.T.Helper()
	p := filepath.Join(e.Dir, rel)
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		e.T.Fatal(err)
	}
	if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
		e.T.Fatal(err)
	}
}

// WriteSecret encrypts plaintext to the environment's recipient as secrets/<name>.age.
func (e *Env) WriteSecret(name, plaintext string) {
	e.T.Helper()
	WriteSecret(e.T, filepath.Join(e.Dir, "secrets"), name, plaintext, e.Recipient)
}

// WriteSecret encrypts plaintext to one age recipient into dir/<name>.age. It is
// the helper that produces the example repository's secret.
func WriteSecret(t *testing.T, dir, name, plaintext, recipient string) {
	t.Helper()
	rs, err := parseRecipient(recipient)
	if err != nil {
		t.Fatal(err)
	}
	st := secrets.NewStore(dir, secrets.Source{}, nil)
	if err := st.Set(name, []byte(plaintext), rs); err != nil {
		t.Fatal(err)
	}
}

// StandardObjects writes a small fleet: one image, two networks, an address
// set, a firewall policy, a backup target and policy (all shared), and the
// given jails on the given hosts.
func (e *Env) StandardObjects() {
	e.std = true
	e.writeMainProject()
	e.Write("shared/images/freebsd-15.yaml", `apiVersion: jailops/v1
kind: Image
metadata:
  name: freebsd-15
spec:
  os: freebsd
  release: 15.0-RELEASE
  arch: amd64
  source:
    type: pkgbase
  aliases: [stable]
`)
	e.Write("shared/networks/internal.yaml", `apiVersion: jailops/v1
kind: Network
metadata:
  name: internal
spec:
  ipv4:
    subnet: 10.20.0.0/24
    gateway: 10.20.0.1
    range: 10.20.0.10-10.20.0.100
`)
	e.Write("shared/networks/dmz.yaml", `apiVersion: jailops/v1
kind: Network
metadata:
  name: dmz
spec:
  ipv4:
    subnet: 10.30.0.0/24
    gateway: 10.30.0.1
    range: 10.30.0.10-10.30.0.100
`)
	e.Write("projects/"+Project+"/address-sets/office.yaml", `apiVersion: jailops/v1
kind: AddressSet
metadata:
  name: office
spec:
  addresses: [{address: 203.0.113.0/28}, {address: 198.51.100.7}]
`)
	e.Write("projects/"+Project+"/firewall-policies/web.yaml", `apiVersion: jailops/v1
kind: FirewallPolicy
metadata:
  name: web
spec:
  default_in: deny
  default_out: allow
  rules:
    - name: https
      action: allow
      direction: in
      proto: tcp
      ports: ["443"]
      from: ["set:office"]
`)
	e.Write("shared/backup-targets/vault.yaml", `apiVersion: jailops/v1
kind: BackupTarget
metadata:
  name: vault
spec:
  kind: node
  address: https://backup.example.test:8443
  fingerprint: aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899
`)
	e.Write("projects/"+Project+"/backup-policies/nightly.yaml", `apiVersion: jailops/v1
kind: BackupPolicy
metadata:
  name: nightly
spec:
  selector: {tier: web}
  targets: [vault]
  schedule: "17 2 * * *"
  retention: {daily: 7, weekly: 4}
`)
}

// Jail writes a jail declaration on a host.
func (e *Env) Jail(host, name string, labels string, extra string) {
	e.T.Helper()
	e.Write("projects/"+Project+"/jails/"+name+".yaml", "apiVersion: jailops/v1\nkind: Jail\nhosts: ["+host+"]\nmetadata:\n  name: "+name+"\n  labels: {"+labels+"}\n"+extra+"spec:\n  image: freebsd-15@stable\n  storage: default\n  network:\n    - network: internal\n      ipv4: auto\n  firewall:\n    policies: [web]\n")
}
