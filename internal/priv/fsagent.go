package priv

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"sync/atomic"
	"time"

	"golang.org/x/sys/unix"

	"jailops.net/jailops/internal/sys/zfs"
	"jailops.net/jailops/sdk/api"
)

// OpFSAgent starts a file agent (see internal/fsagent) for the caller and returns one end of a socket pair.
const OpFSAgent = "fs.agent"

// Agent modes.
const (
	AgentRead  = "read"
	AgentWrite = "write"
)

// MaxAgents bounds the agents running at once.
const MaxAgents = 16

// AgentSubcommand is the argument that makes the helper binary serve as an agent.
const AgentSubcommand = "fsagent"

// AgentSpecialFlag lets a write agent make device nodes and setuid and setgid files: it is given only for a tree a
// jail controls (jailTreeDepth), never for a jail's container or another dataset.
const AgentSpecialFlag = "-special"

type agentArgs struct {
	Mode string `json:"mode"`
	Root string `json:"root"`
}

const (
	backupSnap   = "jailops-backup-"
	propComplete = "jailops:complete"
)

var reBackupSnapDir = regexp.MustCompile(`^(/.+)/\.zfs/snapshot/(` + backupSnap + `[A-Za-z0-9._:-]{1,100})$`)

// checkAgentRoot decides whether the caller may have an agent in root, and returns the dataset it belongs to.
//
//   - A read agent may read a backup snapshot: root is <mountpoint>/.zfs/snapshot/jailops-backup-*, the
//     mountpoint is that of a managed dataset inside a storage root, and the snapshot carries
//     jailops:managed=on (the backup made it).
//   - A write agent may write a jail being restored: root is the mountpoint of a managed dataset inside a
//     storage root whose jailops:complete is off. A finished jail is never written through an agent, and a
//     storage root itself never.
func (l *Local) checkAgentRoot(ctx context.Context, mode, root string) (dataset string, err error) {
	if !isAdmin(ctx) {
		return "", forbidden("an agent needs the admin assertion")
	}
	if !cleanAbs(root) || len(root) > maxPath {
		return "", forbidden("agent root %q is not a clean absolute path", root)
	}
	mp, snap := root, ""
	switch mode {
	case AgentRead:
		m := reBackupSnapDir.FindStringSubmatch(root)
		if m == nil {
			return "", forbidden("a read agent reads a backup snapshot: <mountpoint>/.zfs/snapshot/%s*", backupSnap)
		}
		mp, snap = m[1], m[2]
	case AgentWrite:
		if l.cfg.isMountRoot(root) {
			return "", forbidden("a write agent is not given a storage root")
		}
	default:
		return "", invalid("agent mode must be %s or %s", AgentRead, AgentWrite)
	}
	if !l.cfg.inMounts(mp) {
		return "", l.cfg.notBelowMount(mp)
	}
	// which dataset is mounted there: the one in the storage root that holds the path
	var root0 string
	for _, e := range l.cfg.reg.active() {
		if within(e.Mount, mp) {
			root0 = e.Dataset
		}
	}
	if root0 == "" {
		return "", forbidden("path %q is outside every registered storage root", mp)
	}
	list, err := l.d.ZFS.List(ctx, zfs.ListOpts{Root: root0, Recursive: true, Types: []string{"filesystem"}, Props: []string{"mountpoint", "mounted"}})
	if err != nil {
		return "", err
	}
	for _, d := range list {
		if d.Props["mountpoint"] == mp && d.Props["mounted"] == "yes" {
			dataset = d.Name
			break
		}
	}
	if dataset == "" {
		return "", forbidden("no mounted dataset of a storage root has the mountpoint %q", mp)
	}
	// What authorises an agent is the helper's own record, not a property: the daemon can set any user property
	// on the datasets it owns (see grants.go).
	switch mode {
	case AgentRead:
		if !l.grants.backupSnapshot(dataset + "@" + snap) {
			return "", forbidden("snapshot %s@%s is not one that a backup asked the helper to make", dataset, snap)
		}
	case AgentWrite:
		if !l.grants.restoringDataset(dataset) {
			return "", forbidden("dataset %s is not being restored: a finished jail is not written through an agent", dataset)
		}
	}
	// the path as the kernel sees it must still be the mountpoint (no symlink in between)
	if r, err := filepath.EvalSymlinks(mp); err != nil || r != mp {
		return "", forbidden("path %q is not a plain path", mp)
	}
	return dataset, nil
}

// agentSpecial reports whether a write agent in root may make device nodes and setuid or setgid files: root is a
// tree a jail controls (a jail's root, root.new and the like, or a volume mounted inside one), below a storage
// mount of mode 0700, so such a file is in reach of the jail and of root only, as the jail's own files are.
func (l *Local) agentSpecial(root string) bool {
	r := l.cfg.mountRel(root)
	return r.root != "" && r.rel != "." && jailTreeDepth(r.rel) > 0
}

var agentsRunning atomic.Int32

// FSAgent starts an agent: a copy of the helper binary that changes its root directory to root and serves the
// file protocol on a socket pair. The returned file is the caller's end; closing it ends the agent.
// MaxAgentLifetime bounds the life of one file agent.
const MaxAgentLifetime = 12 * time.Hour

func (l *Local) FSAgent(ctx context.Context, mode, root string) (*os.File, error) {
	if _, err := l.checkAgentRoot(ctx, mode, root); err != nil {
		return nil, err
	}
	args := []string{AgentSubcommand, "-mode", mode, "-root", root}
	if mode == AgentWrite && l.agentSpecial(root) {
		args = append(args, AgentSpecialFlag)
	}
	if agentsRunning.Add(1) > MaxAgents {
		agentsRunning.Add(-1)
		return nil, api.Errorf(api.CodeBusy, "too many file agents are running (%d)", MaxAgents)
	}
	fds, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_STREAM|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		agentsRunning.Add(-1)
		return nil, err
	}
	mine, theirs := os.NewFile(uintptr(fds[0]), "agent-client"), os.NewFile(uintptr(fds[1]), "agent-server")
	self := l.cfg.HelperPath
	if l.d.AgentBinary != "" {
		self = l.d.AgentBinary
	}
	// An agent that outlives any backup or restore (a client that stopped talking but never closed) is killed.
	actx, cancel := context.WithTimeout(context.Background(), MaxAgentLifetime)
	cmd := exec.CommandContext(actx, self, args...)
	cmd.ExtraFiles = []*os.File{theirs} // fd 3
	cmd.Env = []string{"PATH=/usr/bin:/bin"}
	cmd.Stderr = &agentLog{l: l, mode: mode, root: root}
	if err := cmd.Start(); err != nil {
		mine.Close()
		theirs.Close()
		cancel()
		agentsRunning.Add(-1)
		return nil, api.Errorf(api.CodeInternal, "starting the file agent %s: %v", self, err)
	}
	theirs.Close()
	go func() {
		err := cmd.Wait()
		cancel()
		agentsRunning.Add(-1)
		l.auditAgent(mode, root, err)
	}()
	return mine, nil
}

// agentLog collects the agent's stderr into the helper's log.
type agentLog struct {
	l    *Local
	mode string
	root string
}

func (a *agentLog) Write(p []byte) (int, error) {
	if s := strings.TrimSpace(string(p)); s != "" {
		fmt.Fprintf(os.Stderr, "jailops-priv: file agent (%s %s): %s\n", a.mode, a.root, s)
	}
	return len(p), nil
}

func (l *Local) auditAgent(mode, root string, err error) {
	if err != nil {
		fmt.Fprintf(os.Stderr, "jailops-priv: file agent (%s %s) ended: %v\n", mode, root, err)
	}
}
