package node

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net/http"
	"strings"

	"jailops.net/jailops/internal/node/wire"
	"jailops.net/jailops/internal/repo/datastore"
	"jailops.net/jailops/internal/repo/format"
	"jailops.net/jailops/sdk/api"
)

// The escrow blob is the master key wrapped to offline recovery recipients. It
// is not secret (only the holder of a recovery identity can open it) and the
// node cannot read it; it stores it create-only next to the data it protects.

const (
	escrowDir = "escrow/"
	escrowExt = ".age"
	// MaxEscrowBytes bounds an escrow blob.
	MaxEscrowBytes = 64 << 10
)

// ageHeader starts every binary age file with at least one recipient stanza; the hosts write only this form.
const ageHeader = "age-encryption.org/v1\n-> "

func escrowKey(domain string) string { return escrowDir + domain + escrowExt }

// PutEscrow stores the escrow blob of a key domain, create-only. The same bytes
// again are a success; other bytes for an existing domain are refused (a host
// cannot replace the escrow of a key).
func (n *Node) PutEscrow(ctx context.Context, h Host, domain string, r io.Reader, size int64) error {
	if !format.ValidDomainID(domain) {
		return errf(api.CodeInvalid, "malformed key domain id")
	}
	if err := n.requireOnline(); err != nil {
		return err
	}
	if size <= 0 || size > MaxEscrowBytes {
		return errf(api.CodeInvalid, "an escrow blob has between 1 and %d bytes", MaxEscrowBytes)
	}
	b := make([]byte, size)
	if _, err := io.ReadFull(r, b); err != nil {
		return errf(api.CodeInvalid, "the body is shorter than its declared size")
	}
	if m, _ := r.Read(make([]byte, 1)); m > 0 {
		return errf(api.CodeInvalid, "the body is longer than its declared size")
	}
	// The node cannot open the blob, but it can refuse what is not an age file at all, before it takes the name.
	if !bytes.HasPrefix(b, []byte(ageHeader)) {
		return errf(api.CodeInvalid, "an escrow blob is an age file (it starts with %q)", strings.TrimSpace(ageHeader))
	}
	// The first escrow of a repository that recorded no domain binds it (trust on first use); after that only
	// that domain may be escrowed, by anyone.
	if err := n.bindDomain(ctx, domain); err != nil {
		return err
	}
	err := datastore.PutBytes(ctx, n.be, escrowKey(domain), b, datastore.PutOptions{IfAbsent: true})
	switch {
	case err == nil:
		n.audit(ctx, "host:"+h.Name, "escrow.put", domain, nil, "")
		return nil
	case errors.Is(err, datastore.ErrExists):
		cur, rerr := datastore.ReadAll(ctx, n.be, escrowKey(domain), MaxEscrowBytes)
		if rerr == nil && bytes.Equal(cur, b) {
			return nil
		}
		return errf(api.CodeAlreadyExists, "an escrow blob exists for key domain %s", domain)
	}
	return asAPIError(err)
}

// DeleteEscrow removes the escrow blob of a key domain: an administrator's remedy for a blob that does not open
// with the recovery identity (a host of the key domain may have stored a wrong one first). A host then stores a
// new one with PutEscrow, which is create-only as before. The repository stays bound to its key domain.
func (n *Node) DeleteEscrow(ctx context.Context, domain, actor, remote string) error {
	if !format.ValidDomainID(domain) {
		return errf(api.CodeInvalid, "malformed key domain id")
	}
	if err := n.requireOnline(); err != nil {
		return err
	}
	if _, err := n.be.Head(ctx, escrowKey(domain)); errors.Is(err, datastore.ErrNotFound) {
		return errf(api.CodeNotFound, "no escrow blob for key domain %s", domain)
	} else if err != nil {
		return asAPIError(err)
	}
	if err := n.be.Delete(ctx, escrowKey(domain)); err != nil {
		return asAPIError(err)
	}
	n.audit(ctx, actor, "escrow.delete", domain, nil, remote)
	return nil
}

// GetEscrow returns the escrow blob of a key domain.
func (n *Node) GetEscrow(ctx context.Context, domain string) ([]byte, error) {
	if !format.ValidDomainID(domain) {
		return nil, errf(api.CodeInvalid, "malformed key domain id")
	}
	b, err := datastore.ReadAll(ctx, n.be, escrowKey(domain), MaxEscrowBytes)
	if err != nil {
		return nil, asAPIError(err)
	}
	return b, nil
}

// ListEscrow lists the key domains that have an escrow blob.
func (n *Node) ListEscrow(ctx context.Context) ([]string, error) {
	out := []string{}
	err := n.be.List(ctx, escrowDir, func(o datastore.ObjectInfo) error {
		d := strings.TrimSuffix(strings.TrimPrefix(o.Key, escrowDir), escrowExt)
		if format.ValidDomainID(d) && escrowKey(d) == o.Key {
			out = append(out, d)
		}
		return nil
	})
	return out, asAPIErr(err)
}

func asAPIErr(err error) error {
	if err == nil {
		return nil
	}
	return asAPIError(err)
}

func (n *Node) hPutEscrow(w http.ResponseWriter, r *http.Request, h Host) {
	size, err := bodySize(r)
	if err == nil {
		err = n.PutEscrow(r.Context(), h, r.PathValue("domain"), r.Body, size)
	}
	if err != nil {
		writeErr(w, err)
		return
	}
	writeJSON(w, http.StatusCreated, nil)
}

func (n *Node) hGetEscrow(w http.ResponseWriter, r *http.Request, h Host) {
	b, err := n.GetEscrow(r.Context(), r.PathValue("domain"))
	if err != nil {
		writeErr(w, err)
		return
	}
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Content-Length", itoa(len(b)))
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(b)
}

func (n *Node) hListEscrow(w http.ResponseWriter, r *http.Request, h Host) {
	d, err := n.ListEscrow(r.Context())
	if err != nil {
		writeErr(w, err)
		return
	}
	writeJSON(w, 200, wire.EscrowList{Domains: d})
}

// keyDomain is the key domain the repository is bound to, "" if none yet.
func (n *Node) keyDomain() string {
	n.domainMu.Lock()
	defer n.domainMu.Unlock()
	return n.meta.KeyDomain
}

// bindDomain records domain as the repository's key domain when it has none, and refuses any other afterwards.
func (n *Node) bindDomain(ctx context.Context, domain string) error {
	n.domainMu.Lock()
	defer n.domainMu.Unlock()
	if n.meta.KeyDomain == domain {
		return nil
	}
	if n.meta.KeyDomain != "" {
		return errf(api.CodeForbidden, "the repository belongs to key domain %s", n.meta.KeyDomain)
	}
	m := n.meta
	m.KeyDomain = domain
	if err := putJSON(ctx, n.be, metaKey, m, false); err != nil {
		return asAPIError(err)
	}
	n.meta = m
	n.audit(ctx, "", "domain.bind", domain, nil, "")
	return nil
}
