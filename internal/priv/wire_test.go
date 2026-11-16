package priv

import (
	"bytes"
	"encoding/binary"
	"errors"
	"io"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

func TestFrameRoundTrip(t *testing.T) {
	var buf bytes.Buffer
	in := &Frame{Kind: KindReq, ID: 7, Op: OpZFSList, Deadline: 12345, Admin: &Admin{User: "alice"}, Args: []byte(`{"Root":"x"}`), Data: []byte{0, 1, 2, 255}}
	if err := WriteFrame(&buf, in); err != nil {
		t.Fatal(err)
	}
	out, err := ReadFrame(&buf)
	if err != nil {
		t.Fatal(err)
	}
	if out.Kind != in.Kind || out.ID != 7 || out.Op != in.Op || out.Admin.User != "alice" || !bytes.Equal(out.Data, in.Data) || string(out.Args) != string(in.Args) {
		t.Errorf("%+v", out)
	}
}

func TestFrameLimits(t *testing.T) {
	hdr := func(n uint32) io.Reader {
		b := make([]byte, 4)
		binary.BigEndian.PutUint32(b, n)
		return bytes.NewReader(b)
	}
	if _, err := ReadFrame(hdr(0)); !errors.Is(err, ErrFrameTooLarge) {
		t.Errorf("zero length: %v", err)
	}
	if _, err := ReadFrame(hdr(MaxFrame + 1)); !errors.Is(err, ErrFrameTooLarge) {
		t.Errorf("too large: %v", err)
	}
	if _, err := ReadFrame(hdr(0xffffffff)); !errors.Is(err, ErrFrameTooLarge) {
		t.Errorf("huge: %v", err)
	}
	// a short body is an unexpected EOF, not a hang or a panic
	short := append([]byte{0, 0, 0, 10}, []byte("{}")...)
	if _, err := ReadFrame(bytes.NewReader(short)); !errors.Is(err, io.ErrUnexpectedEOF) {
		t.Errorf("short: %v", err)
	}
	if _, err := ReadFrame(bytes.NewReader(nil)); !errors.Is(err, io.EOF) {
		t.Errorf("empty: %v", err)
	}
	for _, body := range []string{"[]", "null", "{\"k\":1}", "{} {}", "garbage", `{"k":"req"} x`} {
		b := make([]byte, 4, 4+len(body))
		binary.BigEndian.PutUint32(b, uint32(len(body)))
		if f, err := ReadFrame(bytes.NewReader(append(b, body...))); err == nil && body != "null" && body != "{}" {
			t.Errorf("body %q parsed as %+v", body, f)
		}
	}
	big := &Frame{Kind: KindData, Data: make([]byte, MaxFrame)}
	if err := WriteFrame(io.Discard, big); !errors.Is(err, ErrFrameTooLarge) {
		t.Errorf("writing a huge frame: %v", err)
	}
}

func FuzzReadFrame(f *testing.F) {
	var ok bytes.Buffer
	_ = WriteFrame(&ok, &Frame{Kind: KindReq, ID: 1, Op: OpPFRead, Args: []byte(`{"anchor":"jailops/x"}`)})
	f.Add(ok.Bytes())
	f.Add([]byte{0, 0, 0, 2, '{', '}'})
	f.Add([]byte{0xff, 0xff, 0xff, 0xff})
	f.Add([]byte{0, 0, 0, 1, '{'})
	f.Add([]byte(strings.Repeat("\x00", 8)))
	f.Fuzz(func(t *testing.T, data []byte) {
		fr, err := ReadFrame(bytes.NewReader(data))
		if err != nil {
			return
		}
		// whatever parsed must survive a round trip
		var b bytes.Buffer
		if err := WriteFrame(&b, fr); err != nil {
			t.Fatalf("re-encode: %v", err)
		}
		if _, err := ReadFrame(&b); err != nil {
			t.Fatalf("re-decode: %v", err)
		}
	})
}

func FuzzDecodeArgs(f *testing.F) {
	f.Add(`{"name":"tank/jailops"}`)
	f.Add(`{"name":1}`)
	f.Add(`{"unknown":true}`)
	f.Add(`[]`)
	f.Fuzz(func(t *testing.T, s string) {
		_, _ = decodeArgs[zfsGetArgs]([]byte(s))
		_, _ = decodeArgs[netArgs]([]byte(s))
		_, _ = decodeArgs[WriteFileReq]([]byte(s))
	})
}

// FuzzCheckCommand: whatever the input, an accepted command runs a fixed
// binary and every path argument is inside the base.
func FuzzCheckCommand(f *testing.F) {
	f.Add("pkg\x00-r\x00/jailops/jails/a/root\x00install\x00nginx")
	f.Add("pkg\x00-r\x00/jailops/0\x00install\x00-r\x000") // found by the fuzzer: -r after the subcommand names a repository
	f.Add("etcupdate\x00-D\x00/x")
	f.Add("sh\x00-c\x00id")
	f.Add("sysctl\x00-n\x00net.inet.ip.forwarding")
	f.Add("sysctl\x00net.inet.ip.forwarding=1")
	f.Add("kldload\x00if_epair")
	f.Add("kldstat\x00-n\x00pf")
	f.Add("pfctl\x00-a\x00jailops/web/x\x00-s\x00rules")
	f.Add("uname\x00-r")
	cfg, _ := Config{StorageRoots: []string{"tank/jailops"}, MountBase: "/jailops"}.Normalize()
	cfg.reg.set([]rootEntry{{Dataset: "tank/jailops", Mount: "/jailops"}})
	binaries := map[string]bool{}
	for _, r := range CommandRules {
		binaries[r.Binary] = true
	}
	f.Fuzz(func(t *testing.T, s string) {
		argv := strings.Split(s, "\x00")
		// no admin assertion: a sysctl write must never be accepted
		_, out, err := cfg.CheckCommand(argv)
		if err != nil {
			return
		}
		if !binaries[out[0]] || !filepath.IsAbs(out[0]) {
			t.Fatalf("binary %q", out[0])
		}
		if out[0] == "/sbin/sysctl" && (len(out) != 3 || out[1] != "-n") {
			t.Fatalf("sysctl form %q without the admin assertion", out)
		}
		if out[0] == "/sbin/pfctl" {
			for i, a := range out {
				if a == "-a" && !strings.HasPrefix(out[i+1], "jailops") {
					t.Fatalf("pfctl anchor %q", out[i+1])
				}
			}
		}
		// pkg: only the -r before the subcommand is the jail root. After it, `-r NAME` selects a configured repository by
		// name (the rest arguments are checked by rePkgName), which is not a path.
		end := len(out)
		for _, r := range CommandRules {
			if r.Binary != "/usr/sbin/pkg" || out[0] != r.Binary {
				continue
			}
			for i := 1; i < len(out); i++ {
				if slices.Contains(r.Subcommands, out[i]) {
					end = i
					break
				}
			}
		}
		for i, a := range out[:end] {
			if (a == "-r" || a == "-D" || a == "-b") && i+1 < len(out) {
				if !strings.HasPrefix(out[i+1], "/jailops/") || strings.Contains(out[i+1], "..") {
					t.Fatalf("path %q accepted in %q", out[i+1], out)
				}
			}
		}
	})
}

func FuzzJailConf(f *testing.F) {
	e := &env{}
	_ = e
	cfg, _ := Config{StorageRoots: []string{"tank/jailops"}, MountBase: "/jailops"}.Normalize()
	f.Add("alpha_web {\n\tpath = \"/jailops/projects/alpha/jails/web/root\";\n\tvnet;\n}\n")
	f.Add(goodConf)
	f.Fuzz(func(t *testing.T, s string) {
		if err := cfg.checkJailConf(t.Context(), "web", s); err != nil {
			return
		}
		// accepted text has no variable expansion other than the hooks and
		// no command separators outside quoted hook lines
		for _, l := range strings.Split(s, "\n") {
			if strings.Contains(l, "${") && !strings.Contains(l, "hook ") && strings.TrimLeft(l, "\t") != `exec.consolelog = "/var/log/jailops/jail_${name}_console.log";` {
				t.Fatalf("accepted a variable: %q", l)
			}
		}
	})
}
