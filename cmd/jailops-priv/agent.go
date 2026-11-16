package main

import (
	"flag"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"

	"golang.org/x/sys/unix"

	"jailops.net/jailops/internal/fsagent"
	"jailops.net/jailops/internal/priv"
)

// agentMain is `jailops-priv fsagent -mode read|write -root DIR`: the file agent the helper starts for the
// daemon (internal/fsagent). It is started by the helper only, with the daemon's connection as descriptor 3,
// after the helper checked the directory. It changes its root directory to DIR, so nothing else on the host
// is reachable, and serves the file protocol until the connection closes.
func agentMain(args []string, stderr io.Writer, euid int) int {
	fs := flag.NewFlagSet("fsagent", flag.ContinueOnError)
	fs.SetOutput(stderr)
	mode := fs.String("mode", "", "read or write")
	root := fs.String("root", "", "the directory the agent is confined to")
	special := fs.Bool("special", false, "a write agent may make device nodes and setuid and setgid files (a jail's root only)")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if euid != 0 {
		fmt.Fprintln(stderr, "fsagent: must run as root (it is started by jailops-priv)")
		return 1
	}
	if *mode != priv.AgentRead && *mode != priv.AgentWrite {
		fmt.Fprintf(stderr, "fsagent: mode %q\n", *mode)
		return 2
	}
	if !filepath.IsAbs(*root) || filepath.Clean(*root) != *root || *root == "/" {
		fmt.Fprintf(stderr, "fsagent: root %q must be a clean absolute path other than /\n", *root)
		return 2
	}
	f := os.NewFile(3, "agent")
	if f == nil {
		fmt.Fprintln(stderr, "fsagent: no connection on descriptor 3")
		return 2
	}
	conn, err := net.FileConn(f)
	f.Close()
	if err != nil {
		fmt.Fprintf(stderr, "fsagent: descriptor 3 is not a socket: %v\n", err)
		return 2
	}
	defer conn.Close()
	// no core file: an agent holds the contents of files
	_ = unix.Setrlimit(unix.RLIMIT_CORE, &unix.Rlimit{})
	if err := unix.Chroot(*root); err != nil {
		fmt.Fprintf(stderr, "fsagent: chroot %s: %v\n", *root, err)
		return 1
	}
	if err := os.Chdir("/"); err != nil {
		fmt.Fprintf(stderr, "fsagent: chdir: %v\n", err)
		return 1
	}
	if err := fsagent.Serve(conn, fsagent.Config{Mode: fsagent.Mode(*mode), Root: "/", Special: *special && *mode == priv.AgentWrite}); err != nil {
		fmt.Fprintf(stderr, "fsagent: %v\n", err)
		return 1
	}
	return 0
}
