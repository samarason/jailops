package logfwd

import (
	"bufio"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"jailops.net/jailops/sdk/api"
)

// testEnv accepts every file (the tests' files are not root's) and records which were checked.
func testEnv(t *testing.T) (*Env, *[]string) {
	var mu sync.Mutex
	var checked []string
	env := &Env{Hostname: "host1", CheckFile: func(p string, secret bool) error {
		mu.Lock()
		defer mu.Unlock()
		checked = append(checked, p+":"+strconv.FormatBool(secret))
		return nil
	}}
	env.defaults()
	return env, &checked
}

var batch = []Entry{
	{Time: t0, Project: "web", Jail: "a", File: "messages", Line: "first"},
	{Time: t0, Project: "web", Jail: "b", File: "messages", Line: "second\nline"},
}

func send(t *testing.T, k api.LogSink, env *Env, b []Entry) error {
	t.Helper()
	snd, err := newSender(k, env, false)
	if err != nil {
		t.Fatal(err)
	}
	defer snd.close()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	return snd.send(ctx, b)
}

func TestSyslogUDP(t *testing.T) {
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer pc.Close()
	env, _ := testEnv(t)
	k := api.LogSink{Name: "u", Type: api.LogSinkSyslog, To: "udp://" + pc.LocalAddr().String(), Facility: "local7"}
	if k.Plaintext() {
		t.Fatal("loopback is not plaintext over the network")
	}
	if err := send(t, k, env, batch); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 65536)
	for i, want := range []string{`<190>1 2026-11-01T09:30:00.000000Z host1 jailops - log [jailops project="web" jail="a" app="" file="messages"] first`,
		`[jailops project="web" jail="b" app="" file="messages"] second\nline`} {
		_ = pc.SetReadDeadline(time.Now().Add(10 * time.Second))
		n, _, err := pc.ReadFrom(buf)
		if err != nil {
			t.Fatal(err)
		}
		if got := string(buf[:n]); (i == 0 && got != want) || !strings.HasSuffix(got, want) {
			t.Fatalf("datagram %d: %s", i, got)
		}
	}
}

// readFrames reads octet-counted frames from a stream.
func readFrames(t *testing.T, r *bufio.Reader, n int) []string {
	t.Helper()
	var out []string
	for range n {
		ls, err := r.ReadString(' ')
		if err != nil {
			t.Fatal(err)
		}
		l, err := strconv.Atoi(strings.TrimSuffix(ls, " "))
		if err != nil {
			t.Fatalf("frame length %q", ls)
		}
		b := make([]byte, l)
		if _, err := io.ReadFull(r, b); err != nil {
			t.Fatal(err)
		}
		out = append(out, string(b))
	}
	return out
}

// TCP: octet-counted frames; a receiver that went away is noticed and dialled again.
func TestSyslogTCP(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	conns := make(chan net.Conn, 2)
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			conns <- c
		}
	}()
	env, _ := testEnv(t)
	k := api.LogSink{Name: "t", Type: api.LogSinkSyslog, To: "tcp://" + ln.Addr().String()}
	snd, err := newSender(k, env, false)
	if err != nil {
		t.Fatal(err)
	}
	defer snd.close()
	ctx := context.Background()
	if err := snd.send(ctx, batch); err != nil {
		t.Fatal(err)
	}
	c1 := <-conns
	got := readFrames(t, bufio.NewReader(c1), 2)
	if !strings.HasPrefix(got[0], "<134>1 ") || !strings.HasSuffix(got[1], `second\nline`) {
		t.Fatalf("%q", got)
	}
	c1.Close() // the receiver restarts
	waitClosed(t, snd.(*syslogSender))
	if err := snd.send(ctx, batch[:1]); err != nil {
		t.Fatal(err)
	}
	c2 := <-conns
	defer c2.Close()
	if got := readFrames(t, bufio.NewReader(c2), 1); !strings.HasSuffix(got[0], "first") {
		t.Fatalf("%q", got)
	}
}

// waitClosed returns once the sender sees that its receiver closed the connection.
func waitClosed(t *testing.T, s *syslogSender) {
	t.Helper()
	for i := 0; !s.peerClosed(); i++ {
		if i > 10000 {
			t.Fatal("the closed connection was not noticed")
		}
	}
}

// testCA makes a certificate authority and a server certificate for 127.0.0.1.
func testCA(t *testing.T) (caPEM []byte, server tls.Certificate) {
	t.Helper()
	caKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	ca := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "test CA"}, NotBefore: time.Now().Add(-time.Hour),
		NotAfter: time.Now().Add(time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
	caDER, err := x509.CreateCertificate(rand.Reader, ca, ca, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	caCert, _ := x509.ParseCertificate(caDER)
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	leaf := &x509.Certificate{SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: "logs"}, NotBefore: time.Now().Add(-time.Hour),
		NotAfter: time.Now().Add(time.Hour), IPAddresses: []net.IP{net.IPv4(127, 0, 0, 1)}, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	der, err := x509.CreateCertificate(rand.Reader, leaf, caCert, &key.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER}), tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
}

// TLS: the receiver is verified against the CA file; without it (the host's roots) the handshake fails.
func TestSyslogTLS(t *testing.T) {
	caPEM, cert := testCA(t)
	ln, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS12})
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	lines := make(chan []string, 1)
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer c.Close()
				if err := c.(*tls.Conn).Handshake(); err != nil {
					return
				}
				lines <- readFrames(t, bufio.NewReader(c), 2)
			}()
		}
	}()
	dir := t.TempDir()
	caFile := filepath.Join(dir, "ca.pem")
	if err := os.WriteFile(caFile, caPEM, 0o644); err != nil {
		t.Fatal(err)
	}
	env, checked := testEnv(t)
	k := api.LogSink{Name: "s", Type: api.LogSinkSyslog, To: "tls://" + ln.Addr().String(), CAFile: caFile}
	if err := send(t, k, env, batch); err != nil {
		t.Fatal(err)
	}
	if got := <-lines; !strings.Contains(got[0], `jail="a"`) || !strings.HasSuffix(got[1], `second\nline`) {
		t.Fatalf("%q", got)
	}
	if len(*checked) != 1 || (*checked)[0] != caFile+":false" {
		t.Fatalf("checked %v", *checked)
	}
	k.CAFile = ""
	if err := send(t, k, env, batch); err == nil || !strings.Contains(err.Error(), "certificate") {
		t.Fatalf("unverified receiver accepted: %v", err)
	}
	// a CA file the check refuses is never read
	env.CheckFile = func(string, bool) error { return io.ErrUnexpectedEOF }
	k.CAFile = caFile
	if _, err := newSender(k, env, false); err == nil || !strings.Contains(err.Error(), "ca_file") {
		t.Fatalf("%v", err)
	}
}

// Webhook: JSON lines over https, the bearer token from its file, a non-2xx answer is a failure.
func TestWebhook(t *testing.T) {
	var mu sync.Mutex
	var bodies []string
	var auths []string
	status := 200
	ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		mu.Lock()
		defer mu.Unlock()
		bodies = append(bodies, r.Header.Get("Content-Type")+"|"+string(b))
		auths = append(auths, r.Header.Get("Authorization"))
		w.WriteHeader(status)
		_, _ = w.Write([]byte("busy\x1b[2J"))
	}))
	defer ts.Close()
	dir := t.TempDir()
	caFile, tokFile := filepath.Join(dir, "ca.pem"), filepath.Join(dir, "token")
	_ = os.WriteFile(caFile, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: ts.Certificate().Raw}), 0o644)
	_ = os.WriteFile(tokFile, []byte("s3cret-token\n"), 0o600)
	env, checked := testEnv(t)
	k := api.LogSink{Name: "w", Type: api.LogSinkWebhook, To: ts.URL + "/ingest", CAFile: caFile, TokenFile: tokFile}
	if err := send(t, k, env, batch); err != nil {
		t.Fatal(err)
	}
	mu.Lock()
	if len(bodies) != 1 || !strings.HasPrefix(bodies[0], "application/x-ndjson|{") || strings.Count(bodies[0], "\n") != 2 || auths[0] != "Bearer s3cret-token" {
		t.Fatalf("%q %q", bodies, auths)
	}
	status = 503
	mu.Unlock()
	err := send(t, k, env, batch[:1])
	if err == nil || err.Error() != "HTTP 503" {
		t.Fatalf("%v", err)
	}
	if !strings.Contains(strings.Join(*checked, ","), tokFile+":true") {
		t.Fatalf("token file not checked as a secret: %v", *checked)
	}
	// a token file whose first line is empty is refused
	_ = os.WriteFile(tokFile, []byte("\nx\n"), 0o600)
	if _, err := newSender(k, env, false); err == nil || !strings.Contains(err.Error(), "token_file") {
		t.Fatalf("%v", err)
	}
}

func TestTargets(t *testing.T) {
	for _, c := range []struct {
		k         api.LogSink
		tr, hp    string
		plaintext bool
	}{
		{api.LogSink{Name: "a", Type: api.LogSinkSyslog, To: "udp://192.0.2.10"}, "udp", "192.0.2.10:514", true},
		{api.LogSink{Name: "a", Type: api.LogSinkSyslog, To: "tcp://logs.example.com"}, "tcp", "logs.example.com:514", true},
		{api.LogSink{Name: "a", Type: api.LogSinkSyslog, To: "tcp://[::1]:1514"}, "tcp", "[::1]:1514", false},
		{api.LogSink{Name: "a", Type: api.LogSinkSyslog, To: "tls://logs.example.com"}, "tls", "logs.example.com:6514", false},
		{api.LogSink{Name: "a", Type: api.LogSinkWebhook, To: "https://hooks.example.com/x"}, "https", "hooks.example.com:443", false},
	} {
		tr, hp, err := c.k.SinkTarget()
		if err != nil || tr != c.tr || hp != c.hp || c.k.Plaintext() != c.plaintext {
			t.Errorf("%s: %s %s %v plaintext=%v", c.k.To, tr, hp, err, c.k.Plaintext())
		}
	}
}

// A webhook that cannot be reached is named without the query of its URL.
func TestWebhookErrorHidesQuery(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := ln.Addr().String()
	ln.Close() // nothing listens there now
	env, _ := testEnv(t)
	err = send(t, api.LogSink{Name: "w", Type: api.LogSinkWebhook, To: "https://" + addr + "/in?key=s3cret"}, env, batch[:1])
	if err == nil || strings.Contains(err.Error(), "s3cret") || !strings.Contains(err.Error(), "POST https://"+addr+"/in:") {
		t.Fatalf("%v", err)
	}
}

// A webhook that answers with a redirect is a failure: the batch and the token are never sent on to where it points.
func TestWebhookDoesNotFollowRedirects(t *testing.T) {
	var mu sync.Mutex
	var hits []string
	ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		hits = append(hits, r.URL.Path+" "+r.Header.Get("Authorization"))
		mu.Unlock()
		if r.URL.Path == "/ingest" {
			http.Redirect(w, r, "/elsewhere", http.StatusTemporaryRedirect)
			return
		}
		w.WriteHeader(200)
	}))
	defer ts.Close()
	dir := t.TempDir()
	caFile, tokFile := filepath.Join(dir, "ca.pem"), filepath.Join(dir, "token")
	_ = os.WriteFile(caFile, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: ts.Certificate().Raw}), 0o644)
	_ = os.WriteFile(tokFile, []byte("s3cret-token\n"), 0o600)
	env, _ := testEnv(t)
	err := send(t, api.LogSink{Name: "w", Type: api.LogSinkWebhook, To: ts.URL + "/ingest", CAFile: caFile, TokenFile: tokFile}, env, batch)
	if err == nil || !strings.HasPrefix(err.Error(), "HTTP 307") {
		t.Fatalf("a redirect: %v", err)
	}
	mu.Lock()
	defer mu.Unlock()
	if len(hits) != 1 || hits[0] != "/ingest Bearer s3cret-token" {
		t.Fatalf("followed: %q", hits)
	}
}
