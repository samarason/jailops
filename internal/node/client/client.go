package client

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"jailops.net/jailops/internal/supervise"
	"math/rand/v2"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"jailops.net/jailops/internal/auth"
	"jailops.net/jailops/internal/node/wire"
	"jailops.net/jailops/internal/repo/format"
	"jailops.net/jailops/sdk/api"
)

// Config configures a Client.
type Config struct {
	// Address is host:port of the node's host listener.
	Address string
	// Fingerprint pins the node's certificate (hex SHA-256).
	Fingerprint string
	// Cert is the host's client certificate.
	Cert tls.Certificate
	// TLS replaces the pinned configuration entirely (tests).
	TLS *tls.Config
	// Attempts is the number of tries per request (default 5).
	Attempts int
	// BackoffBase and BackoffMax bound the jittered wait between tries (default 200 ms, 5 s).
	BackoffBase, BackoffMax time.Duration
	// Sleep replaces the backoff wait (tests).
	Sleep func(ctx context.Context, d time.Duration) error
	// MaxConns bounds the connections kept (default 32).
	MaxConns int
	// KeyDomain is sent when a session opens: a repository that recorded a key domain refuses another one.
	KeyDomain string
}

// Client is a connection to one backup node. Safe for concurrent use.
type Client struct {
	cfg  Config
	mu   sync.Mutex
	hc   *http.Client
	base string
}

// New returns a client. The connection and the certificate pin are made on first use.
func New(cfg Config) (*Client, error) {
	if cfg.Address == "" {
		return nil, errors.New("client: an address is required")
	}
	if cfg.TLS == nil && cfg.Fingerprint == "" {
		return nil, errors.New("client: a certificate fingerprint is required")
	}
	if cfg.Attempts <= 0 {
		cfg.Attempts = 5
	}
	if cfg.BackoffBase <= 0 {
		cfg.BackoffBase = 200 * time.Millisecond
	}
	if cfg.BackoffMax <= 0 {
		cfg.BackoffMax = 5 * time.Second
	}
	if cfg.MaxConns <= 0 {
		cfg.MaxConns = 32
	}
	return &Client{cfg: cfg, base: "https://" + cfg.Address}, nil
}

func (c *Client) http(ctx context.Context) (*http.Client, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.hc != nil {
		return c.hc, nil
	}
	tc := c.cfg.TLS
	if tc == nil {
		var err error
		tc, err = auth.ClientConfigPinned(ctx, &c.cfg.Cert, c.cfg.Address, c.cfg.Fingerprint)
		if err != nil {
			return nil, err
		}
	}
	tr := &http.Transport{
		TLSClientConfig:       tc,
		ForceAttemptHTTP2:     true,
		MaxIdleConns:          2 * c.cfg.MaxConns,
		MaxIdleConnsPerHost:   c.cfg.MaxConns,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   15 * time.Second,
		ResponseHeaderTimeout: 5 * time.Minute,
		DisableCompression:    true,
		ReadBufferSize:        64 << 10,
		WriteBufferSize:       64 << 10,
		HTTP2: &http.HTTP2Config{
			MaxReceiveBufferPerConnection: 32 << 20,
			MaxReceiveBufferPerStream:     8 << 20,
		},
	}
	c.hc = &http.Client{Transport: tr, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	return c.hc, nil
}

// Close drops idle connections.
func (c *Client) Close() {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.hc != nil {
		c.hc.CloseIdleConnections()
	}
}

// temporary reports whether a request may be tried again.
func temporary(err error) bool {
	var ae *api.Error
	if errors.As(err, &ae) {
		switch ae.Code {
		case api.CodeMaintenance:
			return false // the caller defers the whole run; retrying for a minute helps nobody
		case api.CodeInternal:
			return true
		}
		return false
	}
	return !errors.Is(err, context.Canceled) && !errors.Is(err, context.DeadlineExceeded)
}

func (c *Client) backoff(attempt int) time.Duration {
	ceil := min(c.cfg.BackoffBase<<min(attempt, 20), c.cfg.BackoffMax)
	return max(time.Duration(rand.Int64N(int64(ceil)+1)), c.cfg.BackoffBase/2)
}

func (c *Client) wait(ctx context.Context, d time.Duration) error {
	if c.cfg.Sleep != nil {
		return c.cfg.Sleep(ctx, d)
	}
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-t.C:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

// do sends a request, retrying temporary failures. body is re-readable.
func (c *Client) do(ctx context.Context, method, path string, hdr http.Header, body []byte) (*http.Response, error) {
	hc, err := c.http(ctx)
	if err != nil {
		return nil, err
	}
	var last error
	for attempt := 0; attempt < c.cfg.Attempts; attempt++ {
		if attempt > 0 {
			if err := c.wait(ctx, c.backoff(attempt-1)); err != nil {
				return nil, err
			}
		}
		var rd io.Reader
		if body != nil {
			rd = bytes.NewReader(body)
		}
		req, err := http.NewRequestWithContext(ctx, method, c.base+path, rd)
		if err != nil {
			return nil, err
		}
		for k, v := range hdr {
			req.Header[k] = v
		}
		if body != nil {
			req.ContentLength = int64(len(body))
		}
		resp, err := hc.Do(req)
		if err != nil {
			last = err
			if !temporary(err) || ctx.Err() != nil {
				return nil, err
			}
			continue
		}
		if resp.StatusCode >= 200 && resp.StatusCode < 300 {
			return resp, nil
		}
		aerr := readError(resp)
		last = aerr
		if !temporary(aerr) {
			return nil, aerr
		}
	}
	return nil, last
}

// readError decodes the error envelope; the body is consumed and closed.
func readError(resp *http.Response) error {
	defer resp.Body.Close()
	b, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	var env api.Response
	if json.Unmarshal(b, &env) == nil && env.Error != nil {
		return env.Error
	}
	code := api.CodeInternal
	switch resp.StatusCode {
	case 401:
		code = api.CodeUnauthorized
	case 403:
		code = api.CodeForbidden
	case 404:
		code = api.CodeNotFound
	case 503:
		code = api.CodeMaintenance
	}
	return &api.Error{Code: code, Message: fmt.Sprintf("HTTP %d from the backup node", resp.StatusCode)}
}

// call sends JSON and decodes the metadata of the envelope into out.
func (c *Client) call(ctx context.Context, method, path string, in, out any) error {
	var body []byte
	hdr := http.Header{}
	if in != nil {
		var err error
		if body, err = json.Marshal(in); err != nil {
			return err
		}
		hdr.Set("Content-Type", "application/json")
	}
	resp, err := c.do(ctx, method, path, hdr, body)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	var env api.Response
	if err := json.NewDecoder(io.LimitReader(resp.Body, 64<<20)).Decode(&env); err != nil {
		return fmt.Errorf("client: malformed answer from the backup node: %w", err)
	}
	if env.Type == api.ResponseError && env.Error != nil {
		return env.Error
	}
	if out != nil && len(env.Metadata) > 0 {
		return json.Unmarshal(env.Metadata, out)
	}
	return nil
}

// Info returns the repository description and limits.
func (c *Client) Info(ctx context.Context) (*wire.RepoInfo, error) {
	var out wire.RepoInfo
	if err := c.call(ctx, "GET", wire.Base, nil, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// ErrMissingChunks is returned by Commit when the repository lacks chunks the index references.
type ErrMissingChunks struct {
	Count int
	// First lists up to 20 of the missing ids.
	First []format.ID
}

func (e *ErrMissingChunks) Error() string {
	return fmt.Sprintf("the backup node lacks %d chunk(s) the index references", e.Count)
}

// Uploader opens upload sessions.
type Uploader interface {
	Begin(ctx context.Context, group, snapshot, previous string) (UploadSession, error)
}

// UploadSession is one snapshot upload.
type UploadSession interface {
	ID() string
	Previous() string
	Missing(ctx context.Context, ids []format.ID) ([]format.ID, error)
	PutChunk(ctx context.Context, id format.ID, blob []byte) error
	PutIndex(ctx context.Context, index []byte) error
	PutManifest(ctx context.Context, manifest []byte) error
	Commit(ctx context.Context) (*format.Receipt, error)
	Abort(ctx context.Context) error
}

// Snapshot is a committed snapshot as the node lists it.
type Snapshot = wire.Snapshot

// Reader reads committed snapshots and chunks.
type Reader interface {
	Snapshots(ctx context.Context, group string) ([]Snapshot, error)
	Receipt(ctx context.Context, group, snapshot string) (*format.Receipt, error)
	Index(ctx context.Context, group, snapshot string, off, length int64) (io.ReadCloser, int64, error)
	Manifest(ctx context.Context, group, snapshot string) ([]byte, error)
	Chunk(ctx context.Context, id format.ID) ([]byte, error)
}

var (
	_ Uploader = (*Client)(nil)
	_ Reader   = (*Client)(nil)
)

// Session is an open upload session. It renews its lease on its own.
type Session struct {
	c        *Client
	info     wire.SessionInfo
	index    []byte
	manifest []byte

	stop   chan struct{}
	once   sync.Once
	closed bool
	mu     sync.Mutex
}

// Begin opens the session of a group and starts its heartbeat.
func (c *Client) Begin(ctx context.Context, group, snapshot, previous string) (UploadSession, error) {
	var info wire.SessionInfo
	if err := c.call(ctx, "POST", wire.Base+"/sessions", wire.BeginRequest{Group: group, Snapshot: snapshot, Previous: previous, KeyDomain: c.cfg.KeyDomain}, &info); err != nil {
		return nil, err
	}
	s := &Session{c: c, info: info, stop: make(chan struct{})}
	go func() {
		defer func() { supervise.Report(nil, "upload-heartbeat", recover()) }()
		s.heartbeat()
	}()
	return s, nil
}

func (s *Session) heartbeat() {
	every := time.Duration(s.info.LeaseMs) * time.Millisecond / 3
	if every <= 0 {
		every = 5 * time.Minute
	}
	t := time.NewTicker(every)
	defer t.Stop()
	for {
		select {
		case <-s.stop:
			return
		case <-t.C:
			ctx, cancel := context.WithTimeout(context.Background(), every)
			err := s.c.call(ctx, "POST", s.path("/heartbeat"), nil, nil)
			cancel()
			if api.IsCode(err, api.CodeLeaseExpired) {
				return
			}
		}
	}
}

func (s *Session) path(suffix string) string { return wire.Base + "/sessions/" + s.info.ID + suffix }

func (s *Session) end() { s.once.Do(func() { close(s.stop) }) }

// ID is the session id.
func (s *Session) ID() string { return s.info.ID }

// Previous is the previous snapshot the node pinned ("" if it has none).
func (s *Session) Previous() string { return s.info.Previous }

// Missing asks which of ids the node lacks (at most wire.MaxMissingBatch per call; larger slices are split).
func (s *Session) Missing(ctx context.Context, ids []format.ID) ([]format.ID, error) {
	var out []format.ID
	for len(ids) > 0 {
		n := min(len(ids), wire.MaxMissingBatch)
		req := wire.MissingRequest{IDs: make([]string, n)}
		for i, id := range ids[:n] {
			req.IDs[i] = id.String()
		}
		var resp wire.MissingResponse
		if err := s.c.call(ctx, "POST", s.path("/missing"), req, &resp); err != nil {
			return nil, err
		}
		for _, h := range resp.Missing {
			id, err := format.ParseID(h)
			if err != nil {
				return nil, fmt.Errorf("client: the node returned a malformed id: %w", err)
			}
			out = append(out, id)
		}
		ids = ids[n:]
	}
	return out, nil
}

// PutChunk uploads a chunk blob. A chunk that exists already is success: the
// node keeps the stored object, pins it for this session and says so.
func (s *Session) PutChunk(ctx context.Context, id format.ID, blob []byte) error {
	hdr := http.Header{"Content-Type": {"application/octet-stream"}}
	resp, err := s.c.do(ctx, "PUT", s.path("/chunks/"+id.String()), hdr, blob)
	if err != nil {
		if api.IsCode(err, api.CodeAlreadyExists) {
			return nil
		}
		return err
	}
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 1<<20))
	return resp.Body.Close()
}

func (s *Session) putFile(ctx context.Context, name string, b []byte) (string, error) {
	hdr := http.Header{"Content-Type": {"application/octet-stream"}}
	resp, err := s.c.do(ctx, "PUT", s.path("/"+name), hdr, b)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	var env api.Response
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&env); err != nil {
		return "", err
	}
	var d struct {
		Digest string `json:"digest"`
	}
	_ = json.Unmarshal(env.Metadata, &d)
	return d.Digest, nil
}

// PutIndex uploads the index and checks that the node holds the same bytes.
func (s *Session) PutIndex(ctx context.Context, index []byte) error {
	d, err := s.putFile(ctx, "index", index)
	if err != nil {
		return err
	}
	if d != format.FileDigest(index) {
		return errors.New("client: the node stored a different index than the one sent")
	}
	s.mu.Lock()
	s.index = index
	s.mu.Unlock()
	return nil
}

// PutManifest uploads the manifest and checks that the node holds the same bytes.
func (s *Session) PutManifest(ctx context.Context, manifest []byte) error {
	d, err := s.putFile(ctx, "manifest", manifest)
	if err != nil {
		return err
	}
	if d != format.FileDigest(manifest) {
		return errors.New("client: the node stored a different manifest than the one sent")
	}
	s.mu.Lock()
	s.manifest = manifest
	s.mu.Unlock()
	return nil
}

// Commit asks the node to commit. It names the digests of what it uploaded, so a
// retry whose answer was lost is recognised. When chunks are missing it returns
// *ErrMissingChunks; the session stays open for another try.
func (s *Session) Commit(ctx context.Context) (*format.Receipt, error) {
	s.mu.Lock()
	idx, man := s.index, s.manifest
	s.mu.Unlock()
	req := wire.CommitRequest{}
	if idx != nil {
		req.IndexDigest = format.FileDigest(idx)
	}
	if man != nil {
		req.ManifestDigest = format.FileDigest(man)
	}
	var rc format.Receipt
	err := s.c.call(ctx, "POST", s.path("/commit"), req, &rc)
	var ae *api.Error
	if errors.As(err, &ae) && ae.Code == api.CodeMissingChunks {
		em := &ErrMissingChunks{}
		em.Count, _ = strconv.Atoi(ae.Detail["count"])
		for _, h := range strings.Split(ae.Detail["first"], ",") {
			if id, perr := format.ParseID(h); perr == nil {
				em.First = append(em.First, id)
			}
		}
		return nil, em
	}
	if err != nil {
		return nil, err
	}
	s.end()
	return &rc, nil
}

// Abort ends the session.
func (s *Session) Abort(ctx context.Context) error {
	s.end()
	err := s.c.call(ctx, "DELETE", s.path(""), nil, nil)
	if api.IsCode(err, api.CodeLeaseExpired) {
		return nil
	}
	return err
}

// ---- reads ------------------------------------------------------------------------

// Snapshots lists the committed snapshots of a group, oldest first.
func (c *Client) Snapshots(ctx context.Context, group string) ([]Snapshot, error) {
	var out []Snapshot
	err := c.call(ctx, "GET", wire.Base+"/groups/"+group+"/snapshots", nil, &out)
	return out, err
}

// Groups lists the groups.
func (c *Client) Groups(ctx context.Context) ([]wire.Group, error) {
	var out []wire.Group
	err := c.call(ctx, "GET", wire.Base+"/groups", nil, &out)
	return out, err
}

// Receipt returns the commit receipt of a snapshot.
func (c *Client) Receipt(ctx context.Context, group, snapshot string) (*format.Receipt, error) {
	b, _, err := c.fetch(ctx, wire.Base+"/groups/"+group+"/snapshots/"+snapshot+"/receipt", 0, -1)
	if err != nil {
		return nil, err
	}
	defer b.Close()
	raw, err := io.ReadAll(io.LimitReader(b, 1<<20))
	if err != nil {
		return nil, err
	}
	return format.ParseReceipt(raw)
}

// Index reads the index of a snapshot, or a byte range of it (length < 0: to the end).
// It returns the total size of the index as well.
func (c *Client) Index(ctx context.Context, group, snapshot string, off, length int64) (io.ReadCloser, int64, error) {
	return c.fetch(ctx, wire.Base+"/groups/"+group+"/snapshots/"+snapshot+"/index", off, length)
}

// Manifest reads the encrypted manifest of a snapshot.
func (c *Client) Manifest(ctx context.Context, group, snapshot string) ([]byte, error) {
	b, _, err := c.fetch(ctx, wire.Base+"/groups/"+group+"/snapshots/"+snapshot+"/manifest", 0, -1)
	if err != nil {
		return nil, err
	}
	defer b.Close()
	return io.ReadAll(io.LimitReader(b, format.MaxManifestSize+1))
}

// Chunk reads a chunk blob.
func (c *Client) Chunk(ctx context.Context, id format.ID) ([]byte, error) {
	b, _, err := c.fetch(ctx, wire.Base+"/chunks/"+id.String(), 0, -1)
	if err != nil {
		return nil, err
	}
	defer b.Close()
	return io.ReadAll(io.LimitReader(b, format.MaxBlobSize+1))
}

// ChunkRange reads part of a chunk blob.
func (c *Client) ChunkRange(ctx context.Context, id format.ID, off, length int64) (io.ReadCloser, error) {
	b, _, err := c.fetch(ctx, wire.Base+"/chunks/"+id.String(), off, length)
	return b, err
}

func (c *Client) fetch(ctx context.Context, path string, off, length int64) (io.ReadCloser, int64, error) {
	hdr := http.Header{}
	if off != 0 || length >= 0 {
		r := fmt.Sprintf("bytes=%d-", off)
		if length >= 0 {
			r = fmt.Sprintf("bytes=%d-%d", off, off+length-1)
		}
		hdr.Set("Range", r)
	}
	resp, err := c.do(ctx, "GET", path, hdr, nil)
	if err != nil {
		return nil, 0, err
	}
	total := resp.ContentLength
	if cr := resp.Header.Get("Content-Range"); cr != "" {
		if _, after, ok := strings.Cut(cr, "/"); ok {
			if n, err := strconv.ParseInt(after, 10, 64); err == nil {
				total = n
			}
		}
	}
	return resp.Body, total, nil
}

// RecordRestoreTest reports the result of a restore test run on this host.
func (c *Client) RecordRestoreTest(ctx context.Context, rt wire.RestoreTest) error {
	return c.call(ctx, "POST", wire.Base+"/restore-tests", rt, nil)
}

// ---- escrow ---------------------------------------------------------------------------

// PutEscrow stores the escrow blob (the master key wrapped to offline recovery
// recipients) of a key domain. It cannot replace one that exists.
func (c *Client) PutEscrow(ctx context.Context, domain string, blob []byte) error {
	resp, err := c.do(ctx, "PUT", wire.Base+"/escrow/"+domain, http.Header{"Content-Type": {"application/octet-stream"}}, blob)
	if err != nil {
		return err
	}
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 1<<20))
	return resp.Body.Close()
}

// GetEscrow returns the escrow blob of a key domain.
func (c *Client) GetEscrow(ctx context.Context, domain string) ([]byte, error) {
	b, _, err := c.fetch(ctx, wire.Base+"/escrow/"+domain, 0, -1)
	if err != nil {
		return nil, err
	}
	defer b.Close()
	return io.ReadAll(io.LimitReader(b, 64<<10+1))
}

// ListEscrow returns the key domains that have an escrow blob.
func (c *Client) ListEscrow(ctx context.Context) ([]string, error) {
	var out wire.EscrowList
	err := c.call(ctx, "GET", wire.Base+"/escrow", nil, &out)
	return out.Domains, err
}

// HasEscrow reports whether the repository holds an escrow blob for the key domain.
func (c *Client) HasEscrow(ctx context.Context, domain string) (bool, error) {
	d, err := c.ListEscrow(ctx)
	if err != nil {
		return false, err
	}
	for _, x := range d {
		if x == domain {
			return true, nil
		}
	}
	return false, nil
}
