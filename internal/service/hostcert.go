package service

import (
	"context"
	"fmt"
	"slices"
	"strconv"
	"strings"

	"jailops.net/jailops/sdk/api"
)

// The certificate of the console and the API (docs/exposure.md). The daemon's TLS listener owns it (internal/daemon);
// the service checks who may change it, records the change and adds what only the service knows: whether the host
// firewall module renders the redirect of an ACME challenge, and the command a client uses to add this host.

// CertificateManager is the certificate of the TLS listener.
type CertificateManager interface {
	// Status describes the served certificate and its source; Redirect and RemoteAdd are left to the service.
	Status(ctx context.Context) api.HostCertificate
	// Upload validates a certificate chain and key and serves them from the next handshake on.
	Upload(ctx context.Context, in api.HostCertificateUpload, by string) error
	// UseACME stores spec as the source and starts a request at once.
	UseACME(ctx context.Context, spec api.ACMESpec, by string) error
	// UseSelfSigned goes back to the generated certificate.
	UseSelfSigned(ctx context.Context, by string) error
	// Redirect is the challenge redirect the host firewall renders while ACME is the source, nil otherwise.
	Redirect() *api.HostFirewallACME
	// ServingFingerprint is the pin of the certificate served now.
	ServingFingerprint() string
	// Checks are the doctor's tls.certificate and tls.acme checks.
	Checks(ctx context.Context) []api.DoctorCheck
}

func (s *Service) certificates() (CertificateManager, error) {
	if s.d.Certificates == nil {
		return nil, api.Errorf(api.CodeUnsupported, "this daemon does not manage a TLS certificate")
	}
	return s.d.Certificates, nil
}

// HostCertificate answers GET /api/v1/host/certificate.
func (s *Service) HostCertificate(ctx context.Context) (api.HostCertificate, error) {
	if err := requireGlobal(ctx, "reading the console's certificate"); err != nil {
		return api.HostCertificate{}, err
	}
	m, err := s.certificates()
	if err != nil {
		return api.HostCertificate{}, err
	}
	st := m.Status(ctx)
	s.decorateCertificate(ctx, &st, m)
	return st, nil
}

// decorateCertificate adds the redirect state and the command a client adds this host with.
func (s *Service) decorateCertificate(ctx context.Context, st *api.HostCertificate, m CertificateManager) {
	if r := m.Redirect(); r != nil {
		red := &api.ACMERedirect{}
		if fw, ok := s.d.Host.(HostFirewallSystem); ok && s.d.Host != nil {
			if fst, err := fw.HostFirewallRead(ctx); err == nil {
				red.Managed = s.hostConfigured(api.HostModuleFirewall) && slices.Contains(fst.Modules, api.HostModuleFirewall)
				red.Applied = red.Managed && fst.Applied != nil && fst.Applied.ACME != nil && *fst.Applied.ACME == *r
			}
		}
		if !red.Managed {
			red.Lines = api.ACMERedirectLines(r.Challenge, r.Port)
		}
		st.Redirect = red
	}
	if port := st.Port; st.Listener && port != 0 {
		host := s.d.Hostname
		if st.ACME != nil && len(st.ACME.Spec.Domains) > 0 {
			host = st.ACME.Spec.Domains[0]
		}
		name, _, _ := strings.Cut(host, ".")
		cmd := fmt.Sprintf("jailops remote add %s https://%s:%d --token-file -", name, host, port)
		if !st.Current.PublicCA {
			cmd = fmt.Sprintf("jailops remote add %s https://%s:%d --fingerprint %s --token-file -", name, host, port, st.Current.Fingerprint)
		}
		st.RemoteAdd = cmd
	}
}

func (s *Service) certChange(ctx context.Context, what string, f func(m CertificateManager, by string) error) (api.HostCertificate, error) {
	if err := requireGlobal(ctx, what); err != nil {
		return api.HostCertificate{}, err
	}
	a := ActorFrom(ctx)
	if a.Perm != api.PermAdmin {
		return api.HostCertificate{}, api.Errorf(api.CodeForbidden, "%s needs the admin role", what)
	}
	m, err := s.certificates()
	if err != nil {
		return api.HostCertificate{}, err
	}
	unlock, err := s.locks.tryLock("console certificate", "host/certificate")
	if err != nil {
		return api.HostCertificate{}, err
	}
	err = f(m, a.Name)
	unlock()
	if err != nil {
		return api.HostCertificate{}, err
	}
	s.emit(ctx, "host-certificate-updated", "/api/v1/host/certificate")
	st := m.Status(ctx)
	s.decorateCertificate(ctx, &st, m)
	return st, nil
}

// UploadHostCertificate answers PUT /api/v1/host/certificate.
func (s *Service) UploadHostCertificate(ctx context.Context, in api.HostCertificateUpload) (api.HostCertificate, error) {
	return s.certChange(ctx, "uploading the console's certificate", func(m CertificateManager, by string) error {
		return m.Upload(ctx, in, by)
	})
}

// UseACMECertificate answers POST /api/v1/host/certificate/acme.
func (s *Service) UseACMECertificate(ctx context.Context, spec api.ACMESpec) (api.HostCertificate, error) {
	spec.Enabled = true
	spec = spec.Canonical()
	if err := spec.Validate(); err != nil {
		return api.HostCertificate{}, err
	}
	return s.certChange(ctx, "turning ACME on", func(m CertificateManager, by string) error {
		return m.UseACME(ctx, spec, by)
	})
}

// UseSelfSignedCertificate answers POST /api/v1/host/certificate/self-signed.
func (s *Service) UseSelfSignedCertificate(ctx context.Context) (api.HostCertificate, error) {
	return s.certChange(ctx, "going back to the self-signed certificate", func(m CertificateManager, by string) error {
		return m.UseSelfSigned(ctx, by)
	})
}

// servingFingerprint is what trust tokens pin: the certificate the listener serves now.
func (s *Service) servingFingerprint() string {
	if s.d.Certificates != nil {
		if fp := s.d.Certificates.ServingFingerprint(); fp != "" {
			return fp
		}
	}
	return s.d.ServerFingerprint
}

// doctorTLS reports the served certificate (tls.certificate) and ACME (tls.acme), with the state of the redirect.
func (s *Service) doctorTLS(ctx context.Context, c *checkSet) {
	m := s.d.Certificates
	if m == nil {
		return
	}
	for _, ch := range m.Checks(ctx) {
		if ch.Name == "tls.acme" {
			if r := m.Redirect(); r != nil && ch.Status == api.DoctorOK {
				st := api.HostCertificate{}
				s.decorateCertificate(ctx, &st, m)
				switch {
				case st.Redirect != nil && st.Redirect.Managed && !st.Redirect.Applied:
					ch.Status = api.DoctorWarn
					ch.Message += "; the host firewall does not redirect port " + strconv.Itoa(api.ACMEChallengePort(r.Challenge)) + " yet"
					ch.Hint = "apply the host firewall again (the console's Host page, or jailops host firewall apply): the daemon adds the redirect"
				case st.Redirect != nil && !st.Redirect.Managed:
					ch.Message += "; the redirect of port " + strconv.Itoa(api.ACMEChallengePort(r.Challenge)) + " is in /etc/pf.conf, which JailOps does not manage: it cannot check it"
					if ch.Hint == "" {
						ch.Hint = "pf.conf needs: " + strings.Join(st.Redirect.Lines, " ; ")
					}
				}
			}
		}
		c.list = append(c.list, ch)
	}
}

// doctorAppliance compares the modules the daemon manages with those the helper changes (appliance): both come from
// their own files and from jailops_appliance in rc.conf; a module on one side only answers not_managed.
func (s *Service) doctorAppliance(ctx context.Context, c *checkSet) {
	if s.d.Host == nil {
		return
	}
	st, err := s.d.Host.HostIdentityRead(ctx)
	if err != nil {
		c.add("appliance", api.DoctorUnknown, "cannot ask the helper which host modules it manages: "+err.Error(), "")
		return
	}
	daemon, helper := s.d.HostModules, st.Modules
	var onlyDaemon, onlyHelper []string
	for _, m := range daemon {
		if !slices.Contains(helper, m) {
			onlyDaemon = append(onlyDaemon, m)
		}
	}
	for _, m := range helper {
		if !slices.Contains(daemon, m) {
			onlyHelper = append(onlyHelper, m)
		}
	}
	src := "jailopsd.yaml and priv.conf"
	if len(s.d.ApplianceModules) > 0 {
		src = "jailops_appliance in rc.conf (with jailopsd.yaml and priv.conf)"
	}
	switch {
	case len(onlyDaemon) > 0:
		l := strings.Join(onlyDaemon, ", ")
		c.add("appliance", api.DoctorWarn, "the daemon manages "+l+" but the helper does not, so changes answer not_managed",
			"set jailops_appliance=\"YES\" (and jailops_appliance_modules) in /etc/rc.conf, or add `host-manage = "+strings.Join(onlyDaemon, ",")+
				"` to /usr/local/etc/jailops/priv.conf; then service jailops_priv restart")
	case len(onlyHelper) > 0:
		l := strings.Join(onlyHelper, ", ")
		c.add("appliance", api.DoctorWarn, "the helper manages "+l+" but the daemon does not list it",
			"restart jailopsd so it reads jailops_appliance from /etc/rc.conf (service jailopsd restart), or add "+l+
				" to host.manage.modules of /usr/local/etc/jailops/jailopsd.yaml")
	case len(daemon) == 0:
		c.add("appliance", api.DoctorOK, "off: JailOps does not change the host (jailops_appliance is not set)", "")
	default:
		c.add("appliance", api.DoctorOK, "the daemon and the helper both manage "+strings.Join(daemon, ", ")+" (from "+src+")", "")
	}
}
