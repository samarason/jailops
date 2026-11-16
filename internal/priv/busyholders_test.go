package priv

import (
	"context"
	"errors"
	"strings"
	"testing"

	"jailops.net/jailops/internal/sys/run"
	"jailops.net/jailops/sdk/api"
)

type holderRunner struct{ fstat, mount string }

func (h holderRunner) Run(_ context.Context, c run.Cmd) (run.Result, error) {
	switch c.Name {
	case "/usr/bin/fstat":
		return run.Result{Stdout: []byte(h.fstat)}, nil
	case "/sbin/mount":
		return run.Result{Stdout: []byte(h.mount)}, nil
	}
	return run.Result{}, errors.New("unexpected " + c.Name)
}

// A destroy that stays busy says what holds the mount point: the processes of fstat and the mounts below it.
func TestBusyDestroyNamesTheHolders(t *testing.T) {
	busy := api.Errorf(api.CodeBusy, "cannot unmount '/pool/projects/p/jails/web/root': pool or dataset is busy")
	r := holderRunner{
		fstat: "USER CMD PID FD MOUNT INUM MODE SZ|DV R/W\nroot pkg 4242 wd /pool/projects/p/jails/web/root 2 drwxr-xr-x 5 r\n",
		mount: "devfs on /pool/projects/p/jails/web/root/dev (devfs)\ntank on /other (zfs)\n",
	}
	err := withHolders(context.Background(), r, busy)
	if !api.IsCode(err, api.CodeBusy) {
		t.Fatalf("the code changed: %v", err)
	}
	msg := err.Error()
	for _, want := range []string{"pool or dataset is busy", "held by:", "pkg 4242", "mount: devfs on /pool/projects/p/jails/web/root/dev"} {
		if !strings.Contains(msg, want) {
			t.Errorf("%q is missing from %q", want, msg)
		}
	}
	if strings.Contains(msg, "/other") {
		t.Errorf("a mount elsewhere is named: %q", msg)
	}
	// nothing holds it that fstat or mount can see: the error is as it was
	if got := withHolders(context.Background(), holderRunner{}, busy); got != busy {
		t.Errorf("an error without holders changed: %v", got)
	}
	// other errors, and no runner, pass through
	other := errors.New("cannot destroy: no such dataset")
	if got := withHolders(context.Background(), r, other); got != other {
		t.Errorf("a different error changed: %v", got)
	}
	if got := withHolders(context.Background(), nil, busy); got != busy {
		t.Errorf("without a runner the error changed: %v", got)
	}
}
