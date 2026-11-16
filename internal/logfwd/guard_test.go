package logfwd

import (
	"bufio"
	"context"
	"errors"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"jailops.net/jailops/sdk/api"
)

// A CA or token file is opened from / one component at a time: a symlink anywhere on the way is refused, and the
// owner and mode are those of the open descriptor.
func TestFilesAreOpenedWithoutSymlinks(t *testing.T) {
	dir := t.TempDir()
	real := filepath.Join(dir, "real")
	if err := os.Mkdir(real, 0o750); err != nil {
		t.Fatal(err)
	}
	tok := filepath.Join(real, "token")
	if err := os.WriteFile(tok, []byte("t0k\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(real, filepath.Join(dir, "link")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(tok, filepath.Join(real, "tokenlink")); err != nil {
		t.Fatal(err)
	}
	f, err := openNoFollow(tok, false)
	if err != nil {
		t.Fatal(err)
	}
	f.Close()
	for _, p := range []string{filepath.Join(dir, "link", "token"), filepath.Join(real, "tokenlink")} {
		if f, err := openNoFollow(p, false); err == nil {
			f.Close()
			t.Errorf("%s was opened through a symlink", p)
		}
		env, _ := testEnv(t)
		if _, err := env.token(p, false); err == nil {
			t.Errorf("the token was read through a symlink: %s", p)
		}
	}
	if _, err := openNoFollow(filepath.Join(dir, "link"), true); err == nil {
		t.Error("a symlinked directory was opened")
	}
	if os.Geteuid() != 0 {
		// the default check runs on the descriptor: the test's file is not root's
		if err := CheckFile(tok, true); err == nil || !strings.Contains(err.Error(), "not owned by root") {
			t.Errorf("a file of another user: %v", err)
		}
		if err := CheckSecretsDir(real); err == nil || !strings.Contains(err.Error(), "not owned by root") {
			t.Errorf("a directory of another user: %v", err)
		}
		env := &Env{Hostname: "h"}
		env.defaults()
		if _, err := env.token(tok, false); err == nil {
			t.Error("the default check accepted a file that is not root's")
		}
	}
	if err := CheckSecretsDir(filepath.Join(dir, "link")); err == nil {
		t.Error("a symlinked secrets directory was accepted")
	}
}

// The files of an API sink lie directly in logging.secrets_dir, checked when the list is stored and again at each
// read (a list stored before the rule existed); the files of jailopsd.yaml may lie anywhere.
func TestAPISinkFilesOnlyInTheSecretsDir(t *testing.T) {
	sec, other := t.TempDir(), t.TempDir()
	in, out := filepath.Join(sec, "hook.token"), filepath.Join(other, "hook.token")
	for _, p := range []string{in, out} {
		if err := os.WriteFile(p, []byte("s3cret\n"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	env, _ := testEnv(t)
	env.SecretsDir = sec
	var dirChecked []string
	env.CheckDir = func(d string) error { dirChecked = append(dirChecked, d); return nil }
	k := api.LogSink{Name: "w", Type: api.LogSinkWebhook, To: "https://hooks.example.com/in", TokenFile: out}
	if err := env.CheckAPISink(k); !api.IsCode(err, api.CodeInvalid) || !strings.Contains(err.Error(), "directly in "+sec) {
		t.Fatalf("a token outside the secrets dir: %v", err)
	}
	if _, err := newSender(k, env, true); err == nil || !strings.Contains(err.Error(), "token_file") {
		t.Fatalf("read at send time: %v", err)
	}
	if _, err := newSender(k, env, false); err != nil {
		t.Fatalf("a sink of jailopsd.yaml may name any file: %v", err)
	}
	for _, p := range []string{filepath.Join(sec, "sub", "t"), sec + "/../" + filepath.Base(other) + "/hook.token", "/etc/master.passwd"} {
		k.TokenFile = p
		if err := env.CheckAPISink(k); err == nil {
			t.Errorf("%s was accepted", p)
		}
	}
	k.TokenFile = in
	if err := env.CheckAPISink(k); err != nil {
		t.Fatal(err)
	}
	if _, err := newSender(k, env, true); err != nil {
		t.Fatal(err)
	}
	if len(dirChecked) == 0 || dirChecked[0] != sec {
		t.Fatalf("the directory was not checked: %v", dirChecked)
	}
	env.CheckDir = func(string) error { return errors.New("group writable") }
	if _, err := newSender(k, env, true); err == nil {
		t.Fatal("a secrets directory that fails its check was read")
	}
	env.SecretsDir = ""
	if err := env.CheckAPISink(k); err == nil {
		t.Fatal("no secrets directory: a file was accepted")
	}
}

func TestCheckTarget(t *testing.T) {
	local := []netip.Addr{netip.MustParseAddr("192.0.2.5"), netip.MustParseAddr("2001:db8::5")}
	own := []int{39110, 39080}
	for _, c := range []struct {
		to    string
		class string
	}{
		{"127.0.0.1:514", "loopback"},
		{"127.9.9.9:514", "loopback"},
		{"[::1]:514", "loopback"},
		{"[::ffff:127.0.0.1]:514", "loopback"},
		{"169.254.169.254:80", "link-local"},
		{"[fe80::1]:514", "link-local"},
		{"0.0.0.0:514", "unspecified"},
		{"[::]:514", "unspecified"},
		{"239.1.2.3:514", "multicast"},
		{"[ff02::1]:514", "link-local"},
		{"255.255.255.255:514", "broadcast"},
		{"192.0.2.5:39110", "this daemon's port on a local"},
		{"[2001:db8::5]:39080", "this daemon's port on a local"},
		{"192.0.2.5:514", ""},
		{"192.0.2.6:39110", ""},
		{"198.51.100.7:6514", ""},
	} {
		err := CheckTarget(netip.MustParseAddrPort(c.to), own, local)
		var te *TargetError
		if c.class == "" {
			if err != nil {
				t.Errorf("%s: %v", c.to, err)
			}
			continue
		}
		if !errors.As(err, &te) || te.Class != c.class {
			t.Errorf("%s: %v, want %s", c.to, err, c.class)
		}
	}
	env := &Env{}
	env.defaults()
	for _, to := range []string{"tcp://127.0.0.1:1514", "udp://localhost", "tls://[::1]", "tcp://169.254.169.254:80", "udp://[fe80::1]:514", "tcp://LOCALHOST.:514", "tcp://db.localhost:514"} {
		err := env.CheckAPISink(api.LogSink{Name: "a", Type: api.LogSinkSyslog, To: to})
		if !api.IsCode(err, api.CodeInvalid) || !strings.Contains(err.Error(), "target refused") {
			t.Errorf("%s: %v", to, err)
		}
	}
	if err := env.CheckAPISink(api.LogSink{Name: "a", Type: api.LogSinkWebhook, To: "https://127.0.0.1:8443/in"}); err == nil {
		t.Error("a webhook to the loopback address")
	}
	if err := env.CheckAPISink(api.LogSink{Name: "a", Type: api.LogSinkSyslog, To: "tls://logs.example.com"}); err != nil {
		t.Errorf("a name is checked when it is dialled: %v", err)
	}
}

// The dial of an API sink checks the address the name resolved to: a name for the loopback address is refused
// when the socket connects, and nothing reaches the listener. A sink of jailopsd.yaml still delivers there.
func TestAPISinkDialIsGuarded(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	got := make(chan string, 4)
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer c.Close()
				r := bufio.NewReader(c)
				line, _ := r.ReadString(']')
				got <- line
			}()
		}
	}()
	_, port, _ := net.SplitHostPort(ln.Addr().String())
	env := &Env{Hostname: "h"}
	env.defaults()
	k := api.LogSink{Name: "s", Type: api.LogSinkSyslog, To: "tcp://localhost:" + port}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	snd, err := newSender(k, env, true)
	if err != nil {
		t.Fatal(err)
	}
	err = snd.send(ctx, batch[:1])
	snd.close()
	var te *TargetError
	if !errors.As(err, &te) || te.Class != "loopback" || Classify(err) != "target refused: loopback" {
		t.Fatalf("an API sink reached the loopback address through a name: %v", err)
	}
	// the own ports, on an address of the host
	env.OwnPorts = func() []int { p, _ := net.LookupPort("tcp", port); return []int{p} }
	if err := env.CheckTarget(netip.MustParseAddrPort("127.0.0.1:" + port)); err == nil {
		t.Fatal("the daemon's own port")
	}
	snd, err = newSender(k, env, false)
	if err != nil {
		t.Fatal(err)
	}
	defer snd.close()
	if err := snd.send(ctx, batch[:1]); err != nil {
		t.Fatalf("a sink of jailopsd.yaml to the loopback address: %v", err)
	}
	select {
	case l := <-got:
		if !strings.Contains(l, "<134>1 ") {
			t.Fatalf("%q", l)
		}
	case <-ctx.Done():
		t.Fatal("nothing arrived from the file's sink")
	}
	select {
	case l := <-got:
		t.Fatalf("a second connection arrived: %q", l)
	default:
	}
	// a webhook goes through the same dialer
	w := api.LogSink{Name: "w", Type: api.LogSinkWebhook, To: "https://localhost:" + port + "/in"}
	ws, err := newSender(w, env, true)
	if err != nil {
		t.Fatal(err)
	}
	defer ws.close()
	if err := ws.send(ctx, batch[:1]); !errors.As(err, &te) {
		t.Fatalf("a webhook of the API to the loopback address: %v", err)
	}
}

// The forward test answers a short class, never the receiver's words.
func TestClassify(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := ln.Addr().String()
	ln.Close()
	_, derr := net.Dial("tcp", addr)
	for _, c := range []struct {
		err  error
		want string
	}{
		{&HTTPStatusError{Code: 503}, "HTTP 503"},
		{&TargetError{Addr: "127.0.0.1:22", Class: "loopback"}, "target refused: loopback"},
		{&net.DNSError{Err: "no such host", Name: "x.example"}, "dns lookup failed"},
		{derr, "connection refused"},
		{context.DeadlineExceeded, "timeout"},
		{syscall.EHOSTUNREACH, "unreachable"},
		{errors.New("token_file /x: not owned by root"), "token_file unusable"},
		{errors.New("the banner of some other service"), "send failed"},
	} {
		if got := Classify(c.err); got != c.want {
			t.Errorf("%v: %q, want %q", c.err, got, c.want)
		}
	}
}

// The forward test reports the class of a failure.
func TestForwardTestAnswersAClass(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := ln.Addr().String()
	ln.Close()
	f := New(Env{Hostname: "h"})
	k := api.LogSink{Name: "s", Type: api.LogSinkSyslog, To: "tcp://" + addr}
	if res := f.Test(context.Background(), k, false); res.OK || res.Error != "connection refused" {
		t.Fatalf("%+v", res)
	}
	if res := f.Test(context.Background(), k, true); res.OK || res.Error != "target refused: loopback" {
		t.Fatalf("%+v", res)
	}
}
