package daemon_test

import (
	"runtime"
	"strings"
	"testing"

	"jailops.net/jailops/internal/daemon"
)

func TestDevdConfig(t *testing.T) {
	cfg, err := daemon.Decode(strings.NewReader("pool: tank\n"))
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Devd.Pipe != "/var/run/devd.seqpacket.pipe" || cfg.Devd.On() != (runtime.GOOS == "freebsd") {
		t.Errorf("defaults: %+v on=%v", cfg.Devd, cfg.Devd.On())
	}
	cfg, err = daemon.Decode(strings.NewReader("pool: tank\ndevd:\n  enable: false\n  pipe: /tmp/devd.pipe\n"))
	if err != nil || cfg.Devd.On() || cfg.Devd.Pipe != "/tmp/devd.pipe" {
		t.Errorf("%+v %v", cfg.Devd, err)
	}
	cfg, err = daemon.Decode(strings.NewReader("pool: tank\ndevd:\n  enable: true\n"))
	if err != nil || !cfg.Devd.On() {
		t.Errorf("an explicit enable did not hold: %+v %v", cfg.Devd, err)
	}
	for _, pipe := range []string{"devd.pipe", "/var/run/../devd.pipe", "/"} {
		if _, err := daemon.Decode(strings.NewReader("pool: tank\ndevd:\n  pipe: " + pipe + "\n")); err == nil || !strings.Contains(err.Error(), "devd.pipe") {
			t.Errorf("pipe %q: %v", pipe, err)
		}
	}
}
