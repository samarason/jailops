package fake

import (
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"net/http"
	"slices"
	"strings"

	"jailops.net/jailops/sdk/api"
)

// The fake's certificate of the console (extension host_certificate). It starts with a self-signed certificate
// for the fake's host name; an upload is parsed and checked for the host name, ACME is stored as requesting (no
// CA is asked), and self-signed goes back to the first certificate.

type fakeCert struct {
	source api.CertificateSource
	cur    *api.CertificateInfo
	acme   *api.ACMESpec
}

const fakeCertFingerprint = "5e1f5e1f5e1f5e1f5e1f5e1f5e1f5e1f5e1f5e1f5e1f5e1f5e1f5e1f5e1f5e1f"

// certSelfSigned is the generated certificate of the fake host.
func (s *Server) certSelfSigned() api.CertificateInfo {
	now := s.now().UTC()
	return api.CertificateInfo{Subject: "CN=" + s.hostname, Issuer: "CN=" + s.hostname, Names: []string{s.hostname},
		NotBefore: now.AddDate(0, 0, -30), NotAfter: now.AddDate(10, 0, -30), DaysLeft: 3620, Fingerprint: fakeCertFingerprint, SelfSigned: true}
}

// certStatus is the answer of the certificate routes (s.mu held).
func (s *Server) certStatus() api.HostCertificate {
	c := &s.certSt
	if c.cur == nil {
		cur := s.certSelfSigned()
		c.cur, c.source = &cur, api.CertSourceSelfSigned
	}
	st := api.HostCertificate{Kind: api.KindHostCertificate, Source: c.source, Current: *c.cur, Listener: true, Port: fakeConsolePort,
		Stored: c.source != api.CertSourceSelfSigned}
	if c.acme != nil {
		st.ACME = &api.ACMEStatus{Spec: *c.acme, State: "requesting", ChallengePort: 39080, TermsURL: "https://ca.example.com/terms"}
		st.Redirect = &api.ACMERedirect{Lines: api.ACMERedirectLines(c.acme.Challenge, 39080)}
	}
	host := s.hostname
	if c.acme != nil && len(c.acme.Domains) > 0 {
		host = c.acme.Domains[0]
	}
	name, _, _ := strings.Cut(host, ".")
	st.RemoteAdd = "jailops remote add " + name + " https://" + host + ":39110 --token-file -"
	if !st.Current.PublicCA {
		st.RemoteAdd = "jailops remote add " + name + " https://" + host + ":39110 --fingerprint " + st.Current.Fingerprint + " --token-file -"
	}
	return st
}

func (s *Server) handleHostCertificate(w http.ResponseWriter, _ *http.Request) {
	s.mu.Lock()
	st := s.certStatus()
	s.mu.Unlock()
	writeSync(w, 200, st)
}

func (s *Server) handleHostCertificateUpload(w http.ResponseWriter, r *http.Request) {
	in, e := decode[api.HostCertificateUpload](r)
	if e != nil {
		writeErr(w, e)
		return
	}
	blk, _ := pem.Decode([]byte(in.Certificate))
	if blk == nil {
		writeErr(w, api.Errorf(api.CodeInvalid, "certificate: no PEM certificate"))
		return
	}
	cert, err := x509.ParseCertificate(blk.Bytes)
	if err != nil {
		writeErr(w, api.Errorf(api.CodeInvalid, "certificate: %v", err))
		return
	}
	if k, _ := pem.Decode([]byte(in.Key)); k == nil {
		writeErr(w, api.Errorf(api.CodeInvalid, "key: no PEM key"))
		return
	}
	if err := cert.VerifyHostname(in.Hostname); err != nil {
		writeErr(w, api.Errorf(api.CodeInvalid, "the certificate is not valid for %s", in.Hostname))
		return
	}
	sum := sha256.Sum256(cert.Raw)
	names := slices.Clone(cert.DNSNames)
	for _, ip := range cert.IPAddresses {
		names = append(names, ip.String())
	}
	s.mu.Lock()
	now := s.now()
	info := api.CertificateInfo{Subject: cert.Subject.String(), Issuer: cert.Issuer.String(), Names: names, NotBefore: cert.NotBefore,
		NotAfter: cert.NotAfter, DaysLeft: int(cert.NotAfter.Sub(now).Hours() / 24), Fingerprint: hex.EncodeToString(sum[:]),
		SelfSigned: cert.Subject.String() == cert.Issuer.String()}
	s.certSt.cur, s.certSt.source, s.certSt.acme = &info, api.CertSourceUploaded, nil
	st := s.certStatus()
	s.mu.Unlock()
	writeSync(w, 200, st)
}

func (s *Server) handleHostCertificateACME(w http.ResponseWriter, r *http.Request) {
	in, e := decode[api.ACMESpec](r)
	if e != nil {
		writeErr(w, e)
		return
	}
	spec := *in
	spec.Enabled = true
	spec = spec.Canonical()
	if err := spec.Validate(); err != nil {
		writeErr(w, err.(*api.Error))
		return
	}
	s.mu.Lock()
	s.certStatus() // the self-signed one is served until the CA answers
	s.certSt.source, s.certSt.acme = api.CertSourceACME, &spec
	st := s.certStatus()
	s.mu.Unlock()
	writeSync(w, 200, st)
}

func (s *Server) handleHostCertificateSelfSigned(w http.ResponseWriter, _ *http.Request) {
	s.mu.Lock()
	cur := s.certSelfSigned()
	s.certSt = fakeCert{source: api.CertSourceSelfSigned, cur: &cur}
	st := s.certStatus()
	s.mu.Unlock()
	writeSync(w, 200, st)
}
