package priv

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"

	"jailops.net/jailops/sdk/api"
)

const messagesText = "Oct 29 10:00:00 web kernel: one\nOct 29 10:00:01 web sshd[1]: two\nOct 29 10:00:02 web cron[2]: three\n"

// logTree lays out the log directory of jail shop/web with what a real jail
// may hold: active and rotated files, a subdirectory, and the things the
// helper must refuse (symlinks out of and inside the jail, a fifo, hidden
// files, a deeper directory). It returns the log directory.
func logTree(t *testing.T, e *env) string {
	t.Helper()
	root := filepath.Join(e.cfg.MountBase, "projects", "shop", "jails", "web", "root")
	logs := filepath.Join(root, "var", "log")
	mustWrite(t, filepath.Join(root, "etc", "master.passwd"), "root:secret\n")
	mustWrite(t, filepath.Join(logs, "messages"), messagesText)
	mustWrite(t, filepath.Join(logs, "messages.0"), "old\n")
	mustWrite(t, filepath.Join(logs, "messages.1.gz"), "\x1f\x8bnotreally")
	mustWrite(t, filepath.Join(logs, "nginx", "access.log"), "GET /\n")
	mustWrite(t, filepath.Join(logs, "nginx", ".hidden"), "x\n")
	mustWrite(t, filepath.Join(logs, ".hidden"), "x\n")
	mustWrite(t, filepath.Join(logs, "deep", "er", "file.log"), "x\n")
	mustWrite(t, filepath.Join(e.base, "secret"), "host secret\n")
	for link, target := range map[string]string{
		filepath.Join(logs, "escape"):          filepath.Join(e.base, "secret"),
		filepath.Join(logs, "passwd"):          "/etc/passwd",
		filepath.Join(logs, "inside"):          "../../etc/master.passwd",
		filepath.Join(logs, "etcdir"):          "../../etc",
		filepath.Join(logs, "nginx", "escape"): "../../../etc/master.passwd",
	} {
		if err := os.Symlink(target, link); err != nil {
			t.Fatal(err)
		}
	}
	if err := syscall.Mkfifo(filepath.Join(logs, "fifo"), 0o644); err != nil {
		t.Fatal(err)
	}
	// another jail whose log directory is a symlink to the first jail's /etc
	other := filepath.Join(e.cfg.MountBase, "projects", "shop", "jails", "db", "root")
	os.MkdirAll(filepath.Join(other, "var"), 0o755)
	mustWrite(t, filepath.Join(other, "bin", "sh"), "x")
	if err := os.Symlink("../../../web/root/etc", filepath.Join(other, "var", "log")); err != nil {
		t.Fatal(err)
	}
	// a jail whose "root" is a symlink to the first jail's root
	alias := filepath.Join(e.cfg.MountBase, "projects", "shop", "jails", "alias")
	os.MkdirAll(alias, 0o755)
	if err := os.Symlink("../web/root", filepath.Join(alias, "root")); err != nil {
		t.Fatal(err)
	}
	return logs
}

func TestListLogs(t *testing.T) {
	e := newEnv(t)
	logs := logTree(t, e)
	ctx := context.Background()
	files, truncated, err := e.local.ListLogs(ctx, logs)
	if err != nil || truncated {
		t.Fatal(err, truncated)
	}
	var names []string
	for _, f := range files {
		names = append(names, f.Name)
		switch f.Name {
		case "messages":
			if f.Kind != api.JailLogActive || f.Compressed || f.Size != int64(len(messagesText)) || f.ModifiedAt.IsZero() {
				t.Errorf("messages: %+v", f)
			}
		case "messages.0":
			if f.Kind != api.JailLogRotated || f.Compressed {
				t.Errorf("messages.0: %+v", f)
			}
		case "messages.1.gz":
			if f.Kind != api.JailLogRotated || !f.Compressed {
				t.Errorf("messages.1.gz: %+v", f)
			}
		}
	}
	if got, want := strings.Join(names, " "), "messages messages.0 messages.1.gz nginx/access.log"; got != want {
		t.Fatalf("listed %q, want %q", got, want)
	}
	for _, p := range []string{
		logs + "/messages", // a file, not the directory
		logs + "/nginx",    // a subdirectory
		"/",                // the host
		"/var/log",         // the host's logs
		e.cfg.MountBase,    // the storage root itself
		e.cfg.MountBase + "/projects/shop/jails/web/root",                 // a jail root
		e.cfg.MountBase + "/projects/shop/jails/web/root/etc",             // another directory of a jail root
		e.cfg.MountBase + "/images/x/g1/root/var/log",                     // an image root
		e.cfg.MountBase + "/projects/shop/jails/web/var/log",              // the container, not the root
		e.cfg.MountBase + "/projects/shop/jails/web/root/../root/var/log", // not clean
		e.cfg.MountBase + "/projects/shop/jails/db/root/var/log",          // var/log is a symlink into another jail
		e.cfg.MountBase + "/projects/shop/jails/alias/root/var/log",       // root is a symlink to another jail
		e.cfg.MountBase + "/projects/Shop/jails/web/root/var/log",         // not a project name
		"relative/var/log",
		"",
	} {
		if _, _, err := e.local.ListLogs(ctx, p); err == nil {
			t.Errorf("list %q accepted", p)
		} else if !api.IsCode(err, api.CodeForbidden) && !api.IsCode(err, api.CodeInvalid) {
			t.Errorf("list %q: %v", p, err)
		}
	}
	// a stopped jail whose root dataset is not mounted: the mountpoint is empty or missing
	for _, jail := range []string{"empty", "ghost"} {
		p := filepath.Join(e.cfg.MountBase, "projects", "shop", "jails", jail, "root")
		if jail == "empty" {
			os.MkdirAll(p, 0o755)
		}
		_, _, err := e.local.ListLogs(ctx, p+"/var/log")
		var ae *api.Error
		if !asAPIError(err, &ae) || ae.Code != api.CodeNotFound || ae.Detail["missing"] != "root" {
			t.Errorf("%s: %v", jail, err)
		}
	}
	// a mounted root without var/log has no logs
	p := filepath.Join(e.cfg.MountBase, "projects", "shop", "jails", "bare", "root")
	mustWrite(t, filepath.Join(p, "bin", "sh"), "x")
	if files, _, err := e.local.ListLogs(ctx, p+"/var/log"); err != nil || len(files) != 0 {
		t.Errorf("bare: %v %v", files, err)
	}
}

// A directory with more entries than a listing holds, and more
// subdirectories than are listed: the helper reads a bounded number of
// entries and says that the listing is truncated.
func TestListLogsLimits(t *testing.T) {
	var many, dirs string
	f := newFixtureWith(t, func(e *env) {
		many = filepath.Join(e.cfg.MountBase, "projects", "shop", "jails", "web", "root", "var", "log")
		if err := os.MkdirAll(many, 0o755); err != nil {
			t.Fatal(err)
		}
		for i := range MaxLogFiles + 10 {
			if err := os.WriteFile(filepath.Join(many, fmt.Sprintf("f%05d.log", i)), nil, 0o644); err != nil {
				t.Fatal(err)
			}
		}
		dirs = filepath.Join(e.cfg.MountBase, "projects", "shop", "jails", "db", "root", "var", "log")
		for i := range MaxLogDirs + 6 {
			mustWrite(t, filepath.Join(dirs, fmt.Sprintf("d%03d", i), "x.log"), "x\n")
		}
	})
	ctx := context.Background()
	// over the wire: the flag travels with the files
	files, truncated, err := f.client.ListLogs(ctx, many)
	if err != nil || !truncated || len(files) != MaxLogFiles {
		t.Fatalf("%v %v %d", err, truncated, len(files))
	}
	files, truncated, err = f.client.ListLogs(ctx, dirs)
	if err != nil || !truncated || len(files) != MaxLogDirs {
		t.Fatalf("%v %v %d", err, truncated, len(files))
	}
}

func asAPIError(err error, target **api.Error) bool {
	if err == nil {
		return false
	}
	ae, ok := err.(*api.Error)
	*target = ae
	return ok
}

func TestTailFile(t *testing.T) {
	e := newEnv(t)
	logs := logTree(t, e)
	ctx := context.Background()
	n := int64(len(messagesText))
	data, start, size, err := e.local.TailFile(ctx, logs+"/messages", 0, 0)
	if err != nil || start != 0 || size != n || string(data) != messagesText {
		t.Fatalf("%v %d %d %q", err, start, size, data)
	}
	// a window from the end, and a continuation
	data, start, size, err = e.local.TailFile(ctx, logs+"/messages", 0, 10)
	if err != nil || start != n-10 || size != n || string(data) != "2]: three\n" {
		t.Fatalf("%v %d %d %q", err, start, size, data)
	}
	data, start, size, err = e.local.TailFile(ctx, logs+"/messages", 60, 0)
	if err != nil || start != 60 || size != n || string(data) != messagesText[60:] {
		t.Fatalf("%v %d %d %q", err, start, size, data)
	}
	// an offset beyond the end (the file was rotated): read from the beginning
	data, start, _, err = e.local.TailFile(ctx, logs+"/messages", 500, 0)
	if err != nil || start != 0 || string(data) != messagesText {
		t.Fatalf("%v %d %q", err, start, data)
	}
	if _, _, _, err := e.local.TailFile(ctx, logs+"/nginx/access.log", 0, 0); err != nil {
		t.Errorf("subdirectory: %v", err)
	}
	if _, _, _, err := e.local.TailFile(ctx, logs+"/messages.0", 0, 0); err != nil {
		t.Errorf("rotated: %v", err)
	}
	// a missing file is not_found of the "file" kind: the jail is mounted
	var ae *api.Error
	if _, _, _, err := e.local.TailFile(ctx, logs+"/nope", 0, 0); !asAPIError(err, &ae) || ae.Code != api.CodeNotFound || ae.Detail["missing"] != "file" {
		t.Errorf("missing file: %v", err)
	}
	if _, _, _, err := e.local.TailFile(ctx, logs+"/nginx/nope", 0, 0); !asAPIError(err, &ae) || ae.Code != api.CodeNotFound || ae.Detail["missing"] != "file" {
		t.Errorf("missing file in a subdirectory: %v", err)
	}
	// oversized and malformed requests
	if _, _, _, err := e.local.TailFile(ctx, logs+"/messages", 0, MaxTailBytes+1); !api.IsCode(err, api.CodeInvalid) {
		t.Errorf("oversized: %v", err)
	}
	if _, _, _, err := e.local.TailFile(ctx, logs+"/messages", -1, 0); !api.IsCode(err, api.CodeInvalid) {
		t.Errorf("negative offset: %v", err)
	}
	if _, _, _, err := e.local.TailFile(ctx, logs, 0, 0); !api.IsCode(err, api.CodeInvalid) {
		t.Errorf("the directory: %v", err)
	}
	for _, p := range []string{
		logs + "/escape",           // a symlink out of the storage root
		logs + "/passwd",           // a symlink to a host file
		logs + "/inside",           // a symlink to a file of the jail itself
		logs + "/etcdir/passwd",    // through a symlinked directory
		logs + "/nginx/escape",     // from a subdirectory
		logs + "/fifo",             // not a regular file
		logs + "/.hidden",          // a hidden name
		logs + "/nginx/.hidden",    //
		logs + "/deep/er/file.log", // too deep
		logs + "/../log/messages",  // not clean
		logs + "/../../etc/master.passwd",
		"/etc/passwd",
		"/etc/master.passwd",
		e.cfg.MountBase,
		e.cfg.MountBase + "/projects/shop/jails/web/root/etc/master.passwd",
		e.cfg.MountBase + "/projects/shop/jails/web/spec.json",
		e.cfg.MountBase + "/projects/shop/jails/db/root/var/log/master.passwd", // var/log of db is a symlink
		e.cfg.MountBase + "/projects/shop/jails/alias/root/var/log/messages",   // root of alias is a symlink
		e.cfg.MountBase + "/images/x/g1/root/var/log/messages",
		e.cfg.StateDir + "/x",
		e.cfg.ConfDir + "/shop_web.conf",
	} {
		_, _, _, err := e.local.TailFile(ctx, p, 0, 0)
		if err == nil {
			t.Errorf("tail %q accepted", p)
			continue
		}
		if !api.IsCode(err, api.CodeForbidden) && !api.IsCode(err, api.CodeInvalid) {
			t.Errorf("tail %q: %v", p, err)
		}
	}
}

// A path of the class pathJailLog is the same thing for the command rules
// (checkRulePath) as for the operations: the one function decides.
func TestJailLogPathClass(t *testing.T) {
	e := newEnv(t)
	logs := logTree(t, e)
	if err := e.cfg.checkRulePath(pathJailLog, logs); err != nil {
		t.Error(err)
	}
	if err := e.cfg.checkRulePath(pathJailLog, logs+"/nginx/access.log"); err != nil {
		t.Error(err)
	}
	for _, p := range []string{logs + "/a/b/c", e.cfg.MountBase, "/var/log", logs + "/.x", logs + "/x y"} {
		if err := e.cfg.checkRulePath(pathJailLog, p); err == nil {
			t.Errorf("%q accepted", p)
		}
	}
}

func TestLogsOverTheSocket(t *testing.T) {
	var logs string
	f := newFixtureWith(t, func(e *env) { logs = logTree(t, e) })
	ctx := context.Background()
	files, _, err := f.client.ListLogs(ctx, logs)
	if err != nil || len(files) != 4 || files[0].Name != "messages" {
		t.Fatalf("%v %+v", err, files)
	}
	n := int64(len(messagesText))
	data, start, size, err := f.client.TailFile(ctx, logs+"/messages", n-10, 0)
	if err != nil || start != n-10 || size != n || string(data) != "2]: three\n" {
		t.Fatalf("%v %d %d %q", err, start, size, data)
	}
	if _, _, _, err := f.client.TailFile(ctx, logs+"/escape", 0, 0); !api.IsCode(err, api.CodeForbidden) {
		t.Errorf("escape over the wire: %v", err)
	}
	var ae *api.Error
	if _, _, err := f.client.ListLogs(ctx, f.cfg.MountBase+"/projects/shop/jails/ghost/root/var/log"); !asAPIError(err, &ae) || ae.Detail["missing"] != "root" {
		t.Errorf("the missing marker did not travel: %v", err)
	}
}

// A jail that swaps var/log for a symlink between the helper's check and its open cannot make the log
// operations read the rest of its root.
func TestLogDirSwappedAfterTheCheck(t *testing.T) {
	e := newEnv(t)
	logs := logTree(t, e)
	swapped := false
	openBelowHook = func(seg string) {
		if seg != "log" || swapped {
			return
		}
		swapped = true
		if err := os.Rename(logs, logs+".real"); err != nil {
			t.Error(err)
		}
		if err := os.Symlink("../etc", logs); err != nil {
			t.Error(err)
		}
	}
	t.Cleanup(func() { openBelowHook = nil })
	files, _, err := e.local.ListLogs(context.Background(), logs)
	if !swapped {
		t.Fatal("the hook did not run")
	}
	if !api.IsCode(err, api.CodeForbidden) {
		t.Fatalf("listed the swapped directory: %v %+v", err, files)
	}
	if _, _, _, err := e.local.TailFile(context.Background(), logs+"/master.passwd", 0, 0); err == nil {
		t.Fatal("read /etc/master.passwd of the jail through var/log")
	}
}
