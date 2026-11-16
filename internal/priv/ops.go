package priv

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/netip"
	"os"
	"sort"
	"time"

	"jailops.net/jailops/internal/sys/ifconfig"
	"jailops.net/jailops/internal/sys/jailos"
	"jailops.net/jailops/internal/sys/run"
	"jailops.net/jailops/internal/sys/zfs"
)

// Operation names. This list is the whole surface of the helper: there is no
// operation that runs a command the caller names and none that takes a shell
// string. "run.exec" runs only what CommandRules allows.
const (
	OpZFSList           = "zfs.list"
	OpZFSGet            = "zfs.get"
	OpZFSExists         = "zfs.exists"
	OpZFSSet            = "zfs.set"
	OpZFSInherit        = "zfs.inherit"
	OpZFSCreate         = "zfs.create"
	OpZFSClone          = "zfs.clone"
	OpZFSSnapshot       = "zfs.snapshot"
	OpZFSDestroy        = "zfs.destroy"
	OpZFSRename         = "zfs.rename"
	OpZFSRollback       = "zfs.rollback"
	OpZFSHold           = "zfs.hold"
	OpZFSRelease        = "zfs.release"
	OpZFSHolds          = "zfs.holds"
	OpZFSBookmark       = "zfs.bookmark"
	OpZFSWritten        = "zfs.written"
	OpZFSGUID           = "zfs.guid"
	OpZFSClones         = "zfs.clones"
	OpZFSOrigin         = "zfs.origin"
	OpZFSSend           = "zfs.send"
	OpZFSReceive        = "zfs.receive"
	OpZFSReceiveAbort   = "zfs.receive_abort"
	OpZFSReplicate      = "zfs.replicate"
	OpZFSListPools      = "zfs.list_pools"
	OpZFSActiveFeatures = "zfs.active_features"
	OpZFSMount          = "zfs.mount"
	OpZFSUnmount        = "zfs.unmount"

	OpJailCreate = "jail.create"
	OpJailRemove = "jail.remove"
	OpJailExec   = "jail.exec"
	OpJailList   = "jail.list"
	OpJailGet    = "jail.get"

	OpPFValidate    = "pf.validate"
	OpPFLoad        = "pf.load"
	OpPFRead        = "pf.read"
	OpPFFlush       = "pf.flush"
	OpPFTableAdd    = "pf.table_add"
	OpPFTableDelete = "pf.table_delete"
	OpPFTableShow   = "pf.table_show"
	OpPFKillLabel   = "pf.kill_label"

	OpNetList           = "net.list"
	OpNetSetDescription = "net.set_description"
	OpNetEpairCreate    = "net.epair_create"
	OpNetEpairDestroy   = "net.epair_destroy"
	OpNetMoveToJail     = "net.move_to_jail"
	OpNetMoveFromJail   = "net.move_from_jail"
	OpNetSetLink        = "net.set_link"
	OpNetAddrAdd        = "net.addr_add"
	OpNetAddrRemove     = "net.addr_remove"
	OpNetRouteAdd       = "net.route_add"
	OpNetRouteDelete    = "net.route_delete"
	OpNetIPv6Forwarding = "net.ipv6_forwarding"

	OpFSRead     = "fs.read_file"
	OpFSWrite    = "fs.write_file"
	OpFSMkdir    = "fs.mkdir"
	OpFSVolOwner = "fs.volume_owner"
	// fs.source_probe looks at a host directory below an admin-host-mount directory (safefs.go): whether it is on a
	// mount and whether a file can be made in it. It changes nothing but a probe file it removes again.
	OpFSSourceProbe = "fs.source_probe"
	OpFSRemove      = "fs.remove"
	OpFSRemoveAll   = "fs.remove_all"
	// fs.list_logs and fs.tail_file read the log directory of a jail root
	// (logs.go); nothing else, and nothing is written.
	OpFSListLogs = "fs.list_logs"
	// mounts.stale lists the mounts of a kind JailOps makes below the root of a jail that does not run (read-only);
	// jail.heal cleans up after one jail that does not run: those mounts, and what its poststop hook removes (rctl
	// rules, the pf anchor, its links); net.heal destroys the interfaces of the earlier network layout that no jail
	// that runs uses (stalemounts.go, netheal.go).
	OpMountsStale = "mounts.stale"
	OpJailHeal    = "jail.heal"
	OpNetHeal     = "net.heal"
	// dns.unbound writes the names of the running jails for the host's unbound into the one file root named
	// (unbound-conf) and has unbound read it again; the text is made by the helper (dnsunbound.go).
	OpDNSUnbound = "dns.unbound"
	OpFSTailFile = "fs.tail_file"

	OpNetSetMTU = "net.set_mtu"

	OpNDPRouteAdd    = "ndp.route_add"
	OpNDPRouteDelete = "ndp.route_delete"

	OpStorageRegister   = "storage.register"
	OpStorageUnregister = "storage.unregister"
	OpStorageList       = "storage.list"

	OpFSCopyTree = "fs.copy_tree"
	OpFSSeedKeys = "fs.seed_keys"

	OpExecSession = "jail.session"

	// Host management, module identity (host.go): read needs nothing, apply and restore the admin assertion and
	// host-manage = identity in priv.conf.
	OpHostIdentityRead    = "host.identity.read"
	OpHostIdentityApply   = "host.identity.apply"
	OpHostSnapshotList    = "host.snapshot.list"
	OpHostSnapshotRestore = "host.snapshot.restore"
	// Module firewall and commit confirmed (hostfw.go, hostpending.go): the reads need nothing; apply needs the
	// admin assertion and host-manage = firewall, confirm the assertion and the module of the pending change, revert
	// the assertion only.
	OpHostFirewallRead   = "host.firewall.read"
	OpHostFirewallApply  = "host.firewall.apply"
	OpHostPendingRead    = "host.pending.read"
	OpHostPendingConfirm = "host.pending.confirm"
	OpHostPendingRevert  = "host.pending.revert"

	OpSysctl    = "sys.sysctl"
	OpNDPOpen   = "ndp.open"
	OpNDPAnswer = "ndp.answer"
	OpRun       = "run.exec"
)

// ---- argument and result types ----

type zfsReplicateArgs struct {
	Snapshot string            `json:"snapshot"`
	Dst      string            `json:"dst"`
	Props    map[string]string `json:"props,omitempty"`
	// Raw sends the snapshot as stored (zfs send -w): an encrypted volume stays encrypted.
	Raw bool `json:"raw,omitempty"`
}

// replicator is what a ZFS client offers when it can copy a snapshot into a new dataset without the stream passing
// through the caller.
type replicator interface {
	Replicate(ctx context.Context, snapshot, dst string, props map[string]string) error
}

type nameArgs struct {
	Name string `json:"name"`
}
type zfsGetArgs struct {
	Name  string   `json:"name"`
	Props []string `json:"props,omitempty"`
}
type zfsSetArgs struct {
	Name  string            `json:"name"`
	Props map[string]string `json:"props"`
}
type zfsCloneArgs struct {
	Snapshot string            `json:"snapshot"`
	Target   string            `json:"target"`
	Props    map[string]string `json:"props,omitempty"`
	Parents  bool              `json:"parents,omitempty"`
}
type zfsDestroyArgs struct {
	Name string          `json:"name"`
	Opts zfs.DestroyOpts `json:"opts"`
}
type zfsRenameArgs struct {
	From string         `json:"from"`
	To   string         `json:"to"`
	Opts zfs.RenameOpts `json:"opts"`
}
type zfsRollbackArgs struct {
	Snapshot string           `json:"snapshot"`
	Opts     zfs.RollbackOpts `json:"opts"`
}
type zfsHoldArgs struct {
	Tag       string   `json:"tag"`
	Snapshots []string `json:"snapshots"`
}
type zfsBookmarkArgs struct {
	Snapshot string `json:"snapshot"`
	Bookmark string `json:"bookmark"`
}
type zfsWrittenArgs struct {
	Dataset string `json:"dataset"`
	Since   string `json:"since,omitempty"`
}
type guidRes struct {
	V uint64 `json:"v"`
}
type boolRes struct {
	V bool `json:"v"`
}
type strRes struct {
	V string `json:"v"`
}
type strsRes struct {
	V []string `json:"v"`
}
type pfArgs struct {
	Anchor  string   `json:"anchor"`
	Ruleset string   `json:"ruleset,omitempty"`
	Table   string   `json:"table,omitempty"`
	Addrs   []string `json:"addrs,omitempty"`
	Label   string   `json:"label,omitempty"`
}
type jailConfArgs struct {
	Conf string `json:"conf"`
	Name string `json:"name"`
}
type jailGetRes struct {
	Jail  jailos.Jail `json:"jail"`
	Found bool        `json:"found"`
}

// execArgs is the wire form of jailos.ExecOpts; the streams travel as frames.
type execArgs struct {
	Name      string   `json:"name"`
	Argv      []string `json:"argv"`
	User      string   `json:"user,omitempty"`
	Login     bool     `json:"login,omitempty"`
	Stdin     bool     `json:"stdin,omitempty"`
	TimeoutMs int64    `json:"timeout_ms,omitempty"`
}
type runArgs struct {
	Name      string   `json:"name"`
	Args      []string `json:"args,omitempty"`
	Stdin     bool     `json:"stdin,omitempty"`
	TimeoutMs int64    `json:"timeout_ms,omitempty"`
	MaxOutput int      `json:"max_output,omitempty"`
}
type netArgs struct {
	Name   string         `json:"name,omitempty"`
	Iface  string         `json:"iface,omitempty"`
	Desc   string         `json:"desc,omitempty"`
	Jail   string         `json:"jail,omitempty"`
	Up     bool           `json:"up,omitempty"`
	Prefix netip.Prefix   `json:"prefix,omitzero"`
	Route  ifconfig.Route `json:"route,omitzero"`
}
type epairRes struct {
	A string `json:"a"`
	B string `json:"b"`
}
type mtuArgs struct {
	Iface string `json:"iface"`
	MTU   int    `json:"mtu"`
}
type ndpRouteArgs struct {
	Addr  netip.Addr `json:"addr"`
	Iface string     `json:"iface"`
}
type storageArgs struct {
	Dataset string `json:"dataset"`
}
type copyArgs struct {
	Src  string   `json:"src"`
	Dst  string   `json:"dst"`
	Opts CopyOpts `json:"opts"`
}
type sessArgs struct {
	Jail string   `json:"jail"`
	Argv []string `json:"argv"`
	TTY  bool     `json:"tty,omitempty"`
	Rows uint16   `json:"rows,omitempty"`
	Cols uint16   `json:"cols,omitempty"`
	Env  []string `json:"env,omitempty"`
	User string   `json:"user,omitempty"`
}
type sessCtl struct {
	Rows uint16 `json:"rows,omitempty"`
	Cols uint16 `json:"cols,omitempty"`
	Sig  int    `json:"sig,omitempty"`
}
type sessRes struct {
	Exit int `json:"exit"`
}

// ---- server side dispatch ----

// callIO is what a streaming operation sees.
type callIO struct {
	In  io.Reader // request stream; empty reader when the operation takes none
	Out io.Writer // response stream; discards when unused
	// Files are descriptors to send with the reply; the dispatcher closes
	// them afterwards.
	Files []*os.File
	// ErrOut is the second output channel (stderr of a session), Ctl the
	// control frames of the client and Send writes a control frame to it.
	ErrOut io.Writer
	Ctl    <-chan *Frame
	Send   func(*Frame) error
}

type opDef struct {
	name string
	// stream marks operations that may run for a long time (send, receive,
	// exec); they get Limits.MaxStreamTimeout instead of MaxTimeout.
	stream bool
	fn     func(ctx context.Context, h Host, raw json.RawMessage, io *callIO) (any, error)
}

var opTable = map[string]*opDef{}

func decodeArgs[A any](raw json.RawMessage) (A, error) {
	var a A
	if len(raw) == 0 {
		return a, nil
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&a); err != nil {
		return a, invalid("bad arguments: %v", err)
	}
	return a, nil
}

func register[A any](name string, stream bool, fn func(ctx context.Context, h Host, a A, cio *callIO) (any, error)) {
	if _, dup := opTable[name]; dup {
		panic("priv: duplicate operation " + name)
	}
	opTable[name] = &opDef{name: name, stream: stream, fn: func(ctx context.Context, h Host, raw json.RawMessage, cio *callIO) (any, error) {
		a, err := decodeArgs[A](raw)
		if err != nil {
			return nil, err
		}
		return fn(ctx, h, a, cio)
	}}
}

// OperationNames returns the sorted list of supported operations.
func OperationNames() []string {
	out := make([]string, 0, len(opTable))
	for n := range opTable {
		out = append(out, n)
	}
	sort.Strings(out)
	return out
}

// type of result helper for operations that return nothing.
type empty struct{}

func init() {
	register(OpZFSList, false, func(ctx context.Context, h Host, a zfs.ListOpts, _ *callIO) (any, error) {
		return h.ZFS().List(ctx, a)
	})
	register(OpZFSGet, false, func(ctx context.Context, h Host, a zfsGetArgs, _ *callIO) (any, error) {
		return h.ZFS().Get(ctx, a.Name, a.Props...)
	})
	register(OpZFSExists, false, func(ctx context.Context, h Host, a nameArgs, _ *callIO) (any, error) {
		v, err := h.ZFS().Exists(ctx, a.Name)
		return boolRes{v}, err
	})
	register(OpZFSSet, false, func(ctx context.Context, h Host, a zfsSetArgs, _ *callIO) (any, error) {
		return empty{}, h.ZFS().Set(ctx, a.Name, a.Props)
	})
	register(OpZFSInherit, false, func(ctx context.Context, h Host, a zfsGetArgs, _ *callIO) (any, error) {
		return empty{}, h.ZFS().Inherit(ctx, a.Name, a.Props...)
	})
	register(OpZFSCreate, false, func(ctx context.Context, h Host, a zfs.CreateOpts, _ *callIO) (any, error) {
		return empty{}, h.ZFS().Create(ctx, a)
	})
	register(OpZFSClone, false, func(ctx context.Context, h Host, a zfsCloneArgs, _ *callIO) (any, error) {
		return empty{}, h.ZFS().Clone(ctx, a.Snapshot, a.Target, a.Props, a.Parents)
	})
	register(OpZFSSnapshot, false, func(ctx context.Context, h Host, a zfs.SnapshotOpts, _ *callIO) (any, error) {
		return empty{}, h.ZFS().Snapshot(ctx, a)
	})
	register(OpZFSDestroy, false, func(ctx context.Context, h Host, a zfsDestroyArgs, _ *callIO) (any, error) {
		return empty{}, h.ZFS().Destroy(ctx, a.Name, a.Opts)
	})
	register(OpZFSRename, false, func(ctx context.Context, h Host, a zfsRenameArgs, _ *callIO) (any, error) {
		return empty{}, h.ZFS().Rename(ctx, a.From, a.To, a.Opts)
	})
	register(OpZFSRollback, false, func(ctx context.Context, h Host, a zfsRollbackArgs, _ *callIO) (any, error) {
		return empty{}, h.ZFS().Rollback(ctx, a.Snapshot, a.Opts)
	})
	register(OpZFSHold, false, func(ctx context.Context, h Host, a zfsHoldArgs, _ *callIO) (any, error) {
		return empty{}, h.ZFS().Hold(ctx, a.Tag, a.Snapshots...)
	})
	register(OpZFSRelease, false, func(ctx context.Context, h Host, a zfsHoldArgs, _ *callIO) (any, error) {
		return empty{}, h.ZFS().Release(ctx, a.Tag, a.Snapshots...)
	})
	register(OpZFSHolds, false, func(ctx context.Context, h Host, a nameArgs, _ *callIO) (any, error) {
		return h.ZFS().Holds(ctx, a.Name)
	})
	register(OpZFSBookmark, false, func(ctx context.Context, h Host, a zfsBookmarkArgs, _ *callIO) (any, error) {
		return empty{}, h.ZFS().Bookmark(ctx, a.Snapshot, a.Bookmark)
	})
	register(OpZFSWritten, false, func(ctx context.Context, h Host, a zfsWrittenArgs, _ *callIO) (any, error) {
		v, err := h.ZFS().Written(ctx, a.Dataset, a.Since)
		return guidRes{v}, err
	})
	register(OpZFSGUID, false, func(ctx context.Context, h Host, a nameArgs, _ *callIO) (any, error) {
		v, err := h.ZFS().GUID(ctx, a.Name)
		return guidRes{v}, err
	})
	register(OpZFSClones, false, func(ctx context.Context, h Host, a nameArgs, _ *callIO) (any, error) {
		v, err := h.ZFS().Clones(ctx, a.Name)
		return strsRes{v}, err
	})
	register(OpZFSOrigin, false, func(ctx context.Context, h Host, a nameArgs, _ *callIO) (any, error) {
		v, err := h.ZFS().Origin(ctx, a.Name)
		return strRes{v}, err
	})
	register(OpZFSSend, true, func(ctx context.Context, h Host, a zfs.SendOpts, c *callIO) (any, error) {
		// zfs send writes headers and records in small pieces; send them on in full chunks
		w := bufio.NewWriterSize(c.Out, ChunkSize)
		err := h.ZFS().Send(ctx, a, w)
		if ferr := w.Flush(); err == nil {
			err = ferr
		}
		return empty{}, err
	})
	register(OpZFSReceive, true, func(ctx context.Context, h Host, a zfs.ReceiveOpts, c *callIO) (any, error) {
		return empty{}, h.ZFS().Receive(ctx, a, c.In)
	})
	register(OpZFSReplicate, false, func(ctx context.Context, h Host, a zfsReplicateArgs, _ *callIO) (any, error) {
		if a.Raw {
			return empty{}, h.ReplicateRaw(ctx, a.Snapshot, a.Dst, a.Props)
		}
		r, ok := h.ZFS().(replicator)
		if !ok {
			return nil, invalid("this host cannot replicate")
		}
		return empty{}, r.Replicate(ctx, a.Snapshot, a.Dst, a.Props)
	})
	register(OpZFSReceiveAbort, false, func(ctx context.Context, h Host, a nameArgs, _ *callIO) (any, error) {
		return empty{}, h.ZFS().ReceiveAbort(ctx, a.Name)
	})
	register(OpZFSListPools, false, func(ctx context.Context, h Host, _ empty, _ *callIO) (any, error) {
		return h.ZFS().ListPools(ctx)
	})
	register(OpZFSActiveFeatures, false, func(ctx context.Context, h Host, a nameArgs, _ *callIO) (any, error) {
		v, err := h.ZFS().ActiveFeatures(ctx, a.Name)
		return strsRes{v}, err
	})
	register(OpZFSMount, false, func(ctx context.Context, h Host, a nameArgs, _ *callIO) (any, error) {
		return empty{}, h.Mount(ctx, a.Name)
	})
	register(OpZFSUnmount, false, func(ctx context.Context, h Host, a nameArgs, _ *callIO) (any, error) {
		return empty{}, h.Unmount(ctx, a.Name)
	})

	register(OpJailCreate, true, func(ctx context.Context, h Host, a jailConfArgs, _ *callIO) (any, error) {
		return empty{}, h.Jails().Create(ctx, a.Conf, a.Name)
	})
	register(OpJailRemove, true, func(ctx context.Context, h Host, a jailConfArgs, _ *callIO) (any, error) {
		return empty{}, h.Jails().Remove(ctx, a.Conf, a.Name)
	})
	register(OpJailExec, true, func(ctx context.Context, h Host, a execArgs, c *callIO) (any, error) {
		o := jailos.ExecOpts{Argv: a.Argv, User: a.User, Login: a.Login, Stdout: c.Out, Timeout: time.Duration(a.TimeoutMs) * time.Millisecond}
		if a.Stdin {
			o.Stdin = c.In
		}
		res, err := h.Jails().Exec(ctx, a.Name, o)
		return res, err
	})
	register(OpJailList, false, func(ctx context.Context, h Host, _ empty, _ *callIO) (any, error) {
		return h.Jails().List(ctx)
	})
	register(OpJailGet, false, func(ctx context.Context, h Host, a nameArgs, _ *callIO) (any, error) {
		j, ok, err := h.Jails().Get(ctx, a.Name)
		return jailGetRes{j, ok}, err
	})

	register(OpPFValidate, false, func(ctx context.Context, h Host, a pfArgs, _ *callIO) (any, error) {
		v, err := h.PF().Validate(ctx, a.Anchor, a.Ruleset)
		return strRes{v}, err
	})
	register(OpPFLoad, false, func(ctx context.Context, h Host, a pfArgs, _ *callIO) (any, error) {
		return empty{}, h.PF().Load(ctx, a.Anchor, a.Ruleset)
	})
	register(OpPFRead, false, func(ctx context.Context, h Host, a pfArgs, _ *callIO) (any, error) {
		v, err := h.PF().Read(ctx, a.Anchor)
		return strRes{v}, err
	})
	register(OpPFFlush, false, func(ctx context.Context, h Host, a pfArgs, _ *callIO) (any, error) {
		return empty{}, h.PF().Flush(ctx, a.Anchor)
	})
	register(OpPFTableAdd, false, func(ctx context.Context, h Host, a pfArgs, _ *callIO) (any, error) {
		return empty{}, h.PF().TableAdd(ctx, a.Anchor, a.Table, a.Addrs...)
	})
	register(OpPFTableDelete, false, func(ctx context.Context, h Host, a pfArgs, _ *callIO) (any, error) {
		return empty{}, h.PF().TableDelete(ctx, a.Anchor, a.Table, a.Addrs...)
	})
	register(OpPFKillLabel, false, func(ctx context.Context, h Host, a pfArgs, _ *callIO) (any, error) {
		return empty{}, h.PF().KillLabel(ctx, a.Label)
	})
	register(OpPFTableShow, false, func(ctx context.Context, h Host, a pfArgs, _ *callIO) (any, error) {
		v, err := h.PF().TableShow(ctx, a.Anchor, a.Table)
		return strsRes{v}, err
	})

	register(OpNetList, false, func(ctx context.Context, h Host, _ empty, _ *callIO) (any, error) {
		return h.Net().List(ctx)
	})
	register(OpNetSetDescription, false, func(ctx context.Context, h Host, a netArgs, _ *callIO) (any, error) {
		return empty{}, h.Net().SetDescription(ctx, a.Iface, a.Desc)
	})
	register(OpNetEpairCreate, false, func(ctx context.Context, h Host, a netArgs, _ *callIO) (any, error) {
		x, y, err := h.Net().EpairCreate(ctx, a.Name)
		return epairRes{x, y}, err
	})
	register(OpNetEpairDestroy, false, func(ctx context.Context, h Host, a netArgs, _ *callIO) (any, error) {
		return empty{}, h.Net().EpairDestroy(ctx, a.Iface)
	})
	register(OpNetMoveToJail, false, func(ctx context.Context, h Host, a netArgs, _ *callIO) (any, error) {
		return empty{}, h.Net().MoveToJail(ctx, a.Iface, a.Jail)
	})
	register(OpNetMoveFromJail, false, func(ctx context.Context, h Host, a netArgs, _ *callIO) (any, error) {
		return empty{}, h.Net().MoveFromJail(ctx, a.Iface, a.Jail)
	})
	register(OpNetSetLink, false, func(ctx context.Context, h Host, a netArgs, _ *callIO) (any, error) {
		return empty{}, h.Net().SetLink(ctx, a.Iface, a.Up)
	})
	register(OpNetAddrAdd, false, func(ctx context.Context, h Host, a netArgs, _ *callIO) (any, error) {
		return empty{}, h.Net().AddrAdd(ctx, a.Iface, a.Prefix)
	})
	register(OpNetAddrRemove, false, func(ctx context.Context, h Host, a netArgs, _ *callIO) (any, error) {
		return empty{}, h.Net().AddrRemove(ctx, a.Iface, a.Prefix)
	})
	register(OpNetRouteAdd, false, func(ctx context.Context, h Host, a netArgs, _ *callIO) (any, error) {
		return empty{}, h.Net().RouteAdd(ctx, a.Route)
	})
	register(OpNetRouteDelete, false, func(ctx context.Context, h Host, a netArgs, _ *callIO) (any, error) {
		return empty{}, h.Net().RouteDelete(ctx, a.Route)
	})
	register(OpNetIPv6Forwarding, false, func(ctx context.Context, h Host, _ empty, _ *callIO) (any, error) {
		v, err := h.Net().IPv6Forwarding(ctx)
		return boolRes{v}, err
	})

	register(OpNetSetMTU, false, func(ctx context.Context, h Host, a mtuArgs, _ *callIO) (any, error) {
		return empty{}, h.SetMTU(ctx, a.Iface, a.MTU)
	})
	register(OpNDPRouteAdd, false, func(ctx context.Context, h Host, a ndpRouteArgs, _ *callIO) (any, error) {
		return empty{}, h.NDPRouteAdd(ctx, a.Addr, a.Iface)
	})
	register(OpNDPRouteDelete, false, func(ctx context.Context, h Host, a ndpRouteArgs, _ *callIO) (any, error) {
		return empty{}, h.NDPRouteDelete(ctx, a.Addr, a.Iface)
	})
	register(OpStorageRegister, false, func(ctx context.Context, h Host, a storageArgs, _ *callIO) (any, error) {
		return empty{}, h.RegisterStorage(ctx, a.Dataset)
	})
	register(OpStorageUnregister, false, func(ctx context.Context, h Host, a storageArgs, _ *callIO) (any, error) {
		return empty{}, h.UnregisterStorage(ctx, a.Dataset)
	})
	register(OpStorageList, false, func(ctx context.Context, h Host, _ empty, _ *callIO) (any, error) {
		v, err := h.Storages(ctx)
		return strsRes{v}, err
	})
	// fs.copy_tree streams progress as JSON lines (CopyProgress) and ends
	// with the CopyResult.
	register(OpFSCopyTree, true, func(ctx context.Context, h Host, a copyArgs, c *callIO) (any, error) {
		a.Opts.Progress = func(p CopyProgress) {
			if b, err := json.Marshal(p); err == nil {
				_, _ = c.Out.Write(append(b, '\n'))
			}
		}
		res, err := h.CopyTree(ctx, a.Src, a.Dst, a.Opts)
		return res, err
	})

	register(OpExecSession, true, serveSession)
	register(OpFSSeedKeys, true, func(ctx context.Context, h Host, a nameArgs, _ *callIO) (any, error) {
		return h.SeedKeys(ctx, a.Name)
	})

	register(OpFSRead, false, func(ctx context.Context, h Host, a ReadFileReq, _ *callIO) (any, error) {
		b, err := h.ReadFile(ctx, a.Path)
		return dataRes{b}, err
	})
	register(OpFSWrite, false, func(ctx context.Context, h Host, a WriteFileReq, _ *callIO) (any, error) {
		return empty{}, h.WriteFile(ctx, a)
	})
	register(OpFSMkdir, false, func(ctx context.Context, h Host, a MkdirReq, _ *callIO) (any, error) {
		return empty{}, h.MkdirAll(ctx, a)
	})
	register(OpFSVolOwner, false, func(ctx context.Context, h Host, a VolumeOwnerReq, _ *callIO) (any, error) {
		return empty{}, h.SetVolumeOwner(ctx, a)
	})
	register(OpFSSourceProbe, false, func(ctx context.Context, h Host, a SourceProbeReq, _ *callIO) (any, error) {
		return h.ProbeSource(ctx, a)
	})
	register(OpFSRemoveAll, false, func(ctx context.Context, h Host, a RemoveReq, _ *callIO) (any, error) {
		return empty{}, h.RemoveAll(ctx, a.Path)
	})
	register(OpFSRemove, false, func(ctx context.Context, h Host, a RemoveReq, _ *callIO) (any, error) {
		return empty{}, h.Remove(ctx, a.Path)
	})
	register(OpMountsStale, false, func(ctx context.Context, h Host, _ empty, _ *callIO) (any, error) {
		m, err := h.StaleMounts(ctx)
		return StaleMountsRes{Mounts: m}, err
	})
	register(OpJailHeal, false, func(ctx context.Context, h Host, a HealJailReq, _ *callIO) (any, error) {
		return h.HealJail(ctx, a.Jail)
	})
	register(OpNetHeal, false, func(ctx context.Context, h Host, _ empty, _ *callIO) (any, error) {
		return h.HealNetwork(ctx)
	})
	register(OpDNSUnbound, false, func(ctx context.Context, h Host, a DNSUnboundReq, _ *callIO) (any, error) {
		return h.DNSUnbound(ctx, a.Apply)
	})
	register(OpFSListLogs, false, func(ctx context.Context, h Host, a listLogsArgs, _ *callIO) (any, error) {
		files, truncated, err := h.ListLogs(ctx, a.Dir)
		return ListLogsRes{Files: files, Truncated: truncated}, err
	})
	register(OpFSTailFile, false, func(ctx context.Context, h Host, a TailFileReq, _ *callIO) (any, error) {
		data, start, size, err := h.TailFile(ctx, a.Path, a.Offset, a.Max)
		return TailFileRes{Data: data, Start: start, Size: size}, err
	})

	register(OpSysctl, false, func(ctx context.Context, h Host, a nameArgs, _ *callIO) (any, error) {
		v, err := h.Sysctl(ctx, a.Name)
		return strRes{v}, err
	})
	register(OpFSAgent, false, func(ctx context.Context, h Host, a agentArgs, c *callIO) (any, error) {
		f, err := h.FSAgent(ctx, a.Mode, a.Root)
		if err != nil {
			return nil, err
		}
		c.Files = append(c.Files, f)
		return empty{}, nil
	})
	register(OpNDPOpen, false, func(ctx context.Context, h Host, a ndpArgs, c *callIO) (any, error) {
		f, err := h.NDPOpen(ctx, a.Uplink, a.Promisc)
		if err != nil {
			return nil, err
		}
		c.Files = append(c.Files, f)
		return empty{}, nil
	})
	register(OpNDPAnswer, false, func(ctx context.Context, h Host, a NDPAnswerReq, _ *callIO) (any, error) {
		return empty{}, h.NDPAnswer(ctx, a)
	})
	register(OpRun, true, func(ctx context.Context, h Host, a runArgs, c *callIO) (any, error) {
		cmd := run.Cmd{Name: a.Name, Args: a.Args, Stdout: c.Out, Timeout: time.Duration(a.TimeoutMs) * time.Millisecond, MaxOutput: a.MaxOutput}
		if a.Stdin {
			cmd.Stdin = c.In
		}
		return h.Runner().Run(ctx, cmd)
	})
}

type dataRes struct {
	V []byte `json:"v"`
}
