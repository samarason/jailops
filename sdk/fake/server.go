// Package fake is an in-memory implementation of the JailOps wire contract
// (sdk/PROTOCOL.md) as an http.Handler. Tests run the real sdk client against
// it through httptest, so nothing is mocked on the client side.
//
// Everything lives in memory. Operations run in goroutines inside the process
// and can be delayed or failed on purpose; events are served as Server-Sent
// Events with Last-Event-ID replay; ETag and If-Match behave as specified;
// "auto" addresses are allocated from the network range.
package fake

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"slices"
	"strings"
	"sync"
	"time"

	"jailops.net/jailops/sdk/api"
)

// Option configures a Server.
type Option func(*Server)

// WithToken requires "Authorization: Bearer <token>" on every route except
// GET /api/v1.
// The token is a global admin.
func WithToken(tok string) Option {
	return func(s *Server) {
		s.identities[tok] = Identity{Name: "admin", Permission: api.PermAdmin, Global: true, AllRoles: true}
		s.requireAuth = true
	}
}

// WithIdentity adds a bearer token for a caller with a role and a scope. It
// may be repeated; once any token is configured, requests without a known
// credential are unauthorized.
func WithIdentity(token string, id Identity) Option {
	return func(s *Server) {
		if id.Name == "" {
			id.Name = "id-" + token
		}
		s.identities[token] = id
		s.requireAuth = true
	}
}

// WithServerFingerprint sets the certificate fingerprint trust tokens carry
// (default: a per-server fake value).
func WithServerFingerprint(fp string) Option { return func(s *Server) { s.serverFP = normFP(fp) } }

type muxer func(pattern string, h http.HandlerFunc)

// WithExtensions replaces the advertised api_extensions (default api.Extensions).
func WithExtensions(ext ...string) Option { return func(s *Server) { s.extensions = ext } }

// WithSecretsRecipient sets the age public key the server publishes for sealed environment values.
func WithSecretsRecipient(r string) Option { return func(s *Server) { s.secretsRec = r } }

// WithHostName sets the hostname reported by GET /api/v1.
func WithHostName(n string) Option { return func(s *Server) { s.hostname = n } }

// WithSysctl sets a sysctl of the fake host. The fake looks at net.inet6.icmp6.nd6_onlink_ns_rfc4861 when a
// proxy-mode network is created: "0" makes the answer carry the warning of the real daemon.
func WithSysctl(name, value string) Option {
	return func(s *Server) {
		if s.sysctls == nil {
			s.sysctls = map[string]string{}
		}
		s.sysctls[name] = value
	}
}

// WithArch sets the architecture reported by GET /api/v1 (default amd64; ""
// reports none, as a server that could not tell would).
func WithArch(arch string) Option { return func(s *Server) { s.arch = arch } }

// WithRelease sets the release reported as the kernel version by GET /api/v1 (default 15.1-RELEASE; "" reports
// none, as a server that could not read it would). The hints for a missing image name it.
func WithRelease(release string) Option { return func(s *Server) { s.release = release } }

// WithHosts turns the server into a hub: requests carrying ?host=<name> are
// served by the given server (matched by name or host UUID).
func WithHosts(hosts map[string]*Server) Option {
	return func(s *Server) { s.hosts = hosts; s.hub = true }
}

// WithClock replaces time.Now.
func WithClock(now func() time.Time) Option { return func(s *Server) { s.now = now } }

// RecordedRequest is one request seen by the server.
type RecordedRequest struct {
	Method string
	Path   string
	Query  string
	Header http.Header
	Body   []byte
}

type injected struct {
	method, prefix string
	err            *api.Error
	status         int
	times          int
}

// Server is the fake daemon. It is safe for concurrent use.
type Server struct {
	mu   sync.Mutex
	mux  *http.ServeMux
	now  func() time.Time
	uuid string

	identities  map[string]Identity
	requireAuth bool
	serverFP    string
	trustKey    []byte
	trustTokens map[string]*trustRec
	trustFails  map[string]int
	sessions    map[string]*api.Session
	storageStat map[string]api.StorageStatus
	patterns    []string
	offline     map[string]bool
	fleetConds  map[string][]api.Condition
	projects    *kind[api.Project]
	storages    *kind[api.Storage]
	extensions  []string
	secretsRec  string
	hostname    string
	arch        string
	release     string
	hub         bool
	hosts       map[string]*Server

	hostSt   fakeHost     // host management (host.go)
	fwSt     fakeFirewall // the firewall module and commit confirmed (hostfw.go)
	certSt   fakeCert     // the certificate of the console (hostcert.go)
	vol      fakeVolumes  // the passphrases and locks of encrypted volumes (volumes.go)
	jails    *kind[api.Jail]
	volumes  *kind[api.Volume]
	profiles *kind[api.Profile]
	apps     map[string]*appEntry
	// drafts are what GET /api/v1/jails/{name}/app-draft answers (SeedAppDraft), by jail key
	drafts map[string]api.AppDraft
	// access are the grants of installed apps (appaccess.go), by jail key
	access    map[string]*fakeAccess
	execCalls []ExecCall
	// consoles are the sessions of the console protocol (console.go).
	consoles     map[string]*fakeConsole
	consoleCalls []ConsoleCall
	nextConsole  int
	// bkStatus is the backup key: "" none, "present" or "escrowed".
	bkStatus, bkDomain string
	updPkgs            map[string][]api.PackageUpdate
	updFail            map[string]bool
	updReports         map[string]api.UpdateReport
	updHistory         map[string][]api.UpdateRecord
	// usage is what GET .../usage answers per jail (SeedJailUsage); a jail
	// without an entry gets fixed numbers.
	usage map[string]api.JailUsage
	// logs are the log files of each jail (SeedJailLog), by jail key and
	// name below /var/log; a jail without an entry has none. unmounted
	// marks jails whose root cannot be read (SeedJailUnmounted).
	logs      map[string]map[string][]byte
	unmounted map[string]bool
	logReads  int
	fwd       fakeForward
	sysctls   map[string]string // WithSysctl
	images    *kind[api.Image]
	networks  *kind[api.Network]
	policies  *kind[api.FirewallPolicy]
	addrsets  *kind[api.AddressSet]
	targets   *kind[api.BackupTarget]
	bpolicies *kind[api.BackupPolicy]
	backups   *kind[api.Backup]
	remotes   *kind[api.Remote]
	tokens    *kind[api.Token]
	certs     *kind[api.Certificate]
	users     *kind[api.User]
	wireguard *kind[api.WireGuard]
	wgKeys    int // keys handed out by the WireGuard fake

	snapshots map[string][]*api.JailSnapshot   // by jail
	volSnaps  map[string][]*api.VolumeSnapshot // by volume key
	gens      map[string][]*api.ImageGeneration
	genMax    map[string]int            // highest generation number ever used per image: numbers are never reused
	aliases   map[string]map[string]int // image -> alias -> generation number
	imgSame   map[string]bool           // images whose upgrade finds nothing to upgrade (SeedImageCurrent)
	nextJID   int
	streams   int

	ops        map[string]*opState
	opOrder    []string
	opDelay    time.Duration
	opFail     map[string][]*api.Error
	inject     []*injected
	requests   []RecordedRequest
	events     []sseEvent
	nextEvent  int64
	notify     chan struct{}
	drop       chan struct{}
	closed     chan struct{}
	closeOnce  sync.Once
	baseCtx    context.Context
	baseCancel context.CancelFunc
	wg         sync.WaitGroup
}

// New creates an empty server.
func New(opts ...Option) *Server {
	s := &Server{
		now: time.Now, uuid: newUUID(), hostname: "fake-host", arch: "amd64", release: "15.1-RELEASE",
		extensions: slices.Clone(api.Extensions),
		snapshots:  map[string][]*api.JailSnapshot{}, volSnaps: map[string][]*api.VolumeSnapshot{}, access: map[string]*fakeAccess{},
		identities: map[string]Identity{}, trustTokens: map[string]*trustRec{}, trustFails: map[string]int{},
		sessions: map[string]*api.Session{}, storageStat: map[string]api.StorageStatus{},
		offline: map[string]bool{}, fleetConds: map[string][]api.Condition{},
		gens:    map[string][]*api.ImageGeneration{},
		genMax:  map[string]int{},
		aliases: map[string]map[string]int{},
		imgSame: map[string]bool{},
		ops:     map[string]*opState{}, opFail: map[string][]*api.Error{},
		notify: make(chan struct{}), drop: make(chan struct{}), closed: make(chan struct{}),
	}
	s.baseCtx, s.baseCancel = context.WithCancel(context.Background())
	s.trustKey = make([]byte, 32)
	_, _ = rand.Read(s.trustKey)
	for _, o := range opts {
		o(s)
	}
	if s.serverFP == "" {
		s.serverFP = fingerprintOf([]byte("fake-server-" + s.uuid))
	}
	s.mux = http.NewServeMux()
	s.routes()
	return s
}

// Close stops running operations and ends event streams.
func (s *Server) Close() {
	s.closeOnce.Do(func() {
		close(s.closed)
		s.baseCancel()
	})
	s.wg.Wait()
}

// HostUUID is the UUID this server reports.
func (s *Server) HostUUID() string { return s.uuid }

func newUUID() string {
	var b [16]byte
	_, _ = rand.Read(b[:])
	b[6] = b[6]&0x0f | 0x40
	b[8] = b[8]&0x3f | 0x80
	h := hex.EncodeToString(b[:])
	return h[:8] + "-" + h[8:12] + "-" + h[12:16] + "-" + h[16:20] + "-" + h[20:]
}

func randHex(n int) string {
	b := make([]byte, n)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

// ServeHTTP implements http.Handler.
func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	aggregate := false
	if h := r.URL.Query().Get("host"); h == "all" {
		if !s.hub || r.Method != http.MethodGet || !strings.HasPrefix(r.URL.Path, "/api/v1/projects/") || strings.Count(r.URL.Path, "/") != 4 {
			writeErr(w, api.Errorf(api.CodeInvalid, "host=all is only valid on GET /api/v1/projects/<name> of a hub"))
			return
		}
		aggregate = true
		q := r.URL.Query()
		q.Del("host")
		r = r.Clone(r.Context())
		r.URL.RawQuery = q.Encode()
	} else if h != "" && s.hosts != nil {
		target := s.hosts[h]
		if target == nil {
			for _, t := range s.hosts {
				if t.uuid == h {
					target = t
				}
			}
		}
		if target == nil {
			writeErr(w, api.Errorf(api.CodeNotFound, "unknown host %q", h))
			return
		}
		s.mu.Lock()
		off := s.offline[h] || s.offline[target.uuid]
		s.mu.Unlock()
		if off {
			writeErr(w, api.Errorf(api.CodeBusy, "host %q is offline", h))
			return
		}
		q := r.URL.Query()
		q.Del("host")
		r2 := r.Clone(r.Context())
		r2.URL.RawQuery = q.Encode()
		target.ServeHTTP(w, r2)
		return
	}
	var body []byte
	if r.Body != nil {
		body = readAll(r)
		r.Body = readCloser(body)
	}
	s.mu.Lock()
	s.requests = append(s.requests, RecordedRequest{r.Method, r.URL.Path, r.URL.RawQuery, r.Header.Clone(), redactBody(body)})
	if len(s.requests) > 2000 {
		s.requests = s.requests[1:]
	}
	var inj *injected
	for _, i := range s.inject {
		if i.times != 0 && (i.method == "" || i.method == r.Method) && strings.HasPrefix(r.URL.Path, i.prefix) {
			inj = i
			if i.times > 0 {
				i.times--
			}
			break
		}
	}
	s.mu.Unlock()
	if inj != nil {
		if inj.err != nil {
			writeErr(w, inj.err)
		} else {
			http.Error(w, "injected failure", inj.status)
		}
		return
	}
	_, pattern := s.mux.Handler(r)
	rc, aerr := s.authenticate(r)
	rc.aggregate = aggregate
	if e := s.authorize(rc, pattern, r, aerr); e != nil {
		writeErr(w, e)
		return
	}
	s.mux.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), infoKey{}, rc)))
}

// Requests returns a copy of the request log (newest last, bounded).
func (s *Server) Requests() []RecordedRequest {
	s.mu.Lock()
	defer s.mu.Unlock()
	return slices.Clone(s.requests)
}

// FailRequests makes the next times matching requests fail with err before
// reaching any handler; times < 0 means always. An empty method matches all.
func (s *Server) FailRequests(method, pathPrefix string, err *api.Error, times int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.inject = append(s.inject, &injected{method: method, prefix: pathPrefix, err: err, times: times})
}

// FailStatus is like FailRequests but replies with a bare HTTP status and a
// non-JSON body, to exercise status mapping and retries.
func (s *Server) FailStatus(method, pathPrefix string, status, times int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.inject = append(s.inject, &injected{method: method, prefix: pathPrefix, status: status, times: times})
}

// ClearFailures removes all injected request failures.
func (s *Server) ClearFailures() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.inject = nil
}

// FailOperation makes the next operation with the given key fail with err.
// Keys: "jails.create", "jails.delete", "jails.start", "jails.stop",
// "jails.restart", "jails.rollback", "jails.upgrade", "jails.snapshot",
// "images.build", "images.upgrade", "restores.create".
func (s *Server) FailOperation(key string, err *api.Error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.opFail[key] = append(s.opFail[key], err)
}

// SetOperationDelay makes every operation wait d before doing its work.
func (s *Server) SetOperationDelay(d time.Duration) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.opDelay = d
}

// DisconnectEventStreams ends every open /api/v1/events response, as a network
// drop would, so clients must reconnect.
func (s *Server) DisconnectEventStreams() {
	s.mu.Lock()
	defer s.mu.Unlock()
	close(s.drop)
	s.drop = make(chan struct{})
}

func (s *Server) takeFail(key string) *api.Error {
	q := s.opFail[key]
	if len(q) == 0 {
		return nil
	}
	s.opFail[key] = q[1:]
	return q[0]
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func writeSync(w http.ResponseWriter, status int, meta any) {
	raw, _ := json.Marshal(meta)
	writeJSON(w, status, api.Response{Type: api.ResponseSync, Status: "Success", StatusCode: status, Metadata: raw})
}

func writeErr(w http.ResponseWriter, e *api.Error) {
	st := e.Code.HTTPStatus()
	writeJSON(w, st, api.Response{Type: api.ResponseError, Status: "Failure", StatusCode: st, Error: e})
}
