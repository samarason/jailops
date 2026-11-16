package logfwd

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"slices"
	"strconv"
	"strings"
	"syscall"

	"jailops.net/jailops/sdk/api"
)

// A sink set through the API is restricted: the daemon must not become a way to reach this host's own services or
// the link-local network (a metadata service) for whoever holds an admin token. The check runs on the address the
// name resolved to, when the socket connects, so a name that resolves differently later changes nothing. Sinks of
// jailopsd.yaml, written by root, may name any address.

type restrictedKey struct{}

// restricted marks ctx as the context of a send of an API sink.
func restricted(ctx context.Context) context.Context {
	return context.WithValue(ctx, restrictedKey{}, true)
}

func isRestricted(ctx context.Context) bool {
	v, _ := ctx.Value(restrictedKey{}).(bool)
	return v
}

// TargetError is a destination an API sink may not have.
type TargetError struct {
	Addr  string
	Class string // loopback, link-local, unspecified, multicast, broadcast, this daemon's port
}

func (e *TargetError) Error() string {
	return fmt.Sprintf("target refused: %s is a %s address; a sink set through the API may not send there (name it in logging.forward of jailopsd.yaml)", e.Addr, e.Class)
}

// CheckTarget refuses a destination of an API sink: a loopback, link-local, unspecified, multicast or broadcast
// address, or a port of this daemon on an address of this host.
func CheckTarget(ap netip.AddrPort, ownPorts []int, local []netip.Addr) error {
	a := ap.Addr().Unmap()
	class := ""
	switch {
	case a.IsLoopback():
		class = "loopback"
	case a.IsLinkLocalUnicast() || a.IsLinkLocalMulticast():
		class = "link-local"
	case a.IsUnspecified():
		class = "unspecified"
	case a.IsMulticast():
		class = "multicast"
	case a == netip.AddrFrom4([4]byte{255, 255, 255, 255}):
		class = "broadcast"
	case slices.Contains(ownPorts, int(ap.Port())) && slices.Contains(local, a):
		class = "this daemon's port on a local"
	}
	if class != "" {
		return &TargetError{Addr: ap.String(), Class: class}
	}
	return nil
}

// CheckLiteralTarget refuses at once what the dial would refuse for a host that is an IP address or localhost.
func CheckLiteralTarget(hostport string, ownPorts []int, local []netip.Addr) error {
	host, port, err := net.SplitHostPort(hostport)
	if err != nil {
		return err
	}
	n, _ := strconv.Atoi(port)
	h := strings.ToLower(strings.TrimSuffix(host, "."))
	if h == "localhost" || strings.HasSuffix(h, ".localhost") {
		return &TargetError{Addr: hostport, Class: "loopback"}
	}
	a, err := netip.ParseAddr(host)
	if err != nil {
		return nil // a name: checked when it is dialled
	}
	return CheckTarget(netip.AddrPortFrom(a, uint16(n)), ownPorts, local)
}

// localAddrs are the addresses of this host's interfaces.
func localAddrs() []netip.Addr {
	as, err := net.InterfaceAddrs()
	if err != nil {
		return nil
	}
	var out []netip.Addr
	for _, a := range as {
		if p, err := netip.ParsePrefix(a.String()); err == nil {
			out = append(out, p.Addr().Unmap())
		}
	}
	return out
}

// CheckTarget is CheckTarget with this daemon's ports and addresses, or the test's check.
func (e *Env) CheckTarget(ap netip.AddrPort) error {
	if e.TargetCheck != nil {
		return e.TargetCheck(ap)
	}
	var ports []int
	if e.OwnPorts != nil {
		ports = e.OwnPorts()
	}
	return CheckTarget(ap, ports, localAddrs())
}

// CheckAPISink checks what can be checked of an API sink before it is stored: its files lie directly in the
// secrets directory, that directory is sound, and a literal address is not one the dial would refuse.
func (e *Env) CheckAPISink(k api.LogSink) error {
	for _, f := range []struct{ what, path string }{{"ca_file", k.CAFile}, {"token_file", k.TokenFile}} {
		if f.path == "" {
			continue
		}
		if !inSecretsDir(e.SecretsDir, f.path) {
			return api.Errorf(api.CodeInvalid, "sink %q: %s %s is not a file directly in %s", k.Name, f.what, f.path, e.secretsDirName()).
				WithHint("a sink set through the API reads its files only from logging.secrets_dir (root-owned, 0750 root:jailops); name other files in logging.forward of jailopsd.yaml")
		}
		if err := e.CheckDir(e.SecretsDir); err != nil {
			return api.Errorf(api.CodeInvalid, "sink %q: %s: %v", k.Name, f.what, err).WithHint("make logging.secrets_dir a directory owned by root, mode 0750, group jailops")
		}
	}
	_, hp, err := k.SinkTarget()
	if err != nil {
		return err
	}
	if e.TargetCheck != nil {
		if a, perr := netip.ParseAddrPort(hp); perr == nil {
			err = e.TargetCheck(a)
		}
	} else {
		var ports []int
		if e.OwnPorts != nil {
			ports = e.OwnPorts()
		}
		err = CheckLiteralTarget(hp, ports, localAddrs())
	}
	if err != nil {
		return api.Errorf(api.CodeInvalid, "sink %q: %v", k.Name, err).WithHint("a receiver on this host or on the link-local network is configured in logging.forward of jailopsd.yaml")
	}
	return nil
}

func (e *Env) secretsDirName() string {
	if e.SecretsDir == "" {
		return "logging.secrets_dir (not set)"
	}
	return e.SecretsDir
}

// guardedDialer is the default dialer: for a restricted send it checks the resolved address before connecting.
func (e *Env) guardedDialer() func(ctx context.Context, network, addr string) (net.Conn, error) {
	d := net.Dialer{ControlContext: func(ctx context.Context, network, address string, _ syscall.RawConn) error {
		if !isRestricted(ctx) {
			return nil
		}
		ap, err := netip.ParseAddrPort(address)
		if err != nil {
			return fmt.Errorf("target refused: %s is not an address", address)
		}
		return e.CheckTarget(ap)
	}}
	return d.DialContext
}

// HTTPStatusError is a webhook's answer that is not 2xx. Its body is never kept: it could carry what a service
// on that address had to say, and it is the receiver's business.
type HTTPStatusError struct{ Code int }

func (e *HTTPStatusError) Error() string { return "HTTP " + strconv.Itoa(e.Code) }

// Classify turns a send error into a short fixed class for the answer of a forward test, which names neither the
// receiver's answer nor details of the network.
func Classify(err error) string {
	var te *TargetError
	var he *HTTPStatusError
	var dns *net.DNSError
	var ua x509.UnknownAuthorityError
	var ci x509.CertificateInvalidError
	var hn x509.HostnameError
	var cv *tls.CertificateVerificationError
	var re tls.RecordHeaderError
	var ae tls.AlertError
	var ne net.Error
	msg := err.Error()
	switch {
	case errors.As(err, &te):
		return "target refused: " + te.Class
	case errors.As(err, &he):
		return he.Error()
	case strings.HasPrefix(msg, "token_file"):
		return "token_file unusable"
	case strings.HasPrefix(msg, "ca_file"):
		return "ca_file unusable"
	case errors.As(err, &dns):
		return "dns lookup failed"
	case errors.As(err, &ua), errors.As(err, &ci), errors.As(err, &hn), errors.As(err, &cv):
		return "certificate not trusted"
	case errors.As(err, &re), errors.As(err, &ae), strings.Contains(msg, "tls:"):
		return "tls handshake failed"
	case errors.Is(err, syscall.ECONNREFUSED):
		return "connection refused"
	case errors.Is(err, syscall.ECONNRESET), errors.Is(err, syscall.EPIPE):
		return "connection reset"
	case errors.Is(err, syscall.EHOSTUNREACH), errors.Is(err, syscall.ENETUNREACH):
		return "unreachable"
	case errors.Is(err, context.DeadlineExceeded), errors.As(err, &ne) && ne.Timeout():
		return "timeout"
	}
	return "send failed"
}
