package priv

import (
	"context"
	"io"
	"net/netip"

	"jailops.net/jailops/internal/sys/ifconfig"
	"jailops.net/jailops/internal/sys/jailos"
	"jailops.net/jailops/internal/sys/pfctl"
	"jailops.net/jailops/internal/sys/run"
	"jailops.net/jailops/internal/sys/zfs"
)

// ZFS returns a zfs.Client backed by the helper.
func (c *Client) ZFS() zfs.Client { return zfsClient{c} }

// Jails returns a jailos.Jails backed by the helper.
func (c *Client) Jails() jailos.Jails { return jailClient{c} }

// PF returns a pfctl.Client backed by the helper.
func (c *Client) PF() pfctl.Client { return pfClient{c} }

// Net returns an ifconfig.Client backed by the helper.
func (c *Client) Net() ifconfig.Client { return netClient{c} }

// ---- zfs ----

type zfsClient struct{ c *Client }

var _ zfs.Client = zfsClient{}

func (z zfsClient) List(ctx context.Context, o zfs.ListOpts) ([]zfs.Dataset, error) {
	return callJSON[[]zfs.Dataset](ctx, z.c, OpZFSList, o, callOpts{})
}
func (z zfsClient) Get(ctx context.Context, name string, props ...string) (map[string]zfs.Prop, error) {
	return callJSON[map[string]zfs.Prop](ctx, z.c, OpZFSGet, zfsGetArgs{name, props}, callOpts{})
}
func (z zfsClient) Exists(ctx context.Context, name string) (bool, error) {
	r, err := callJSON[boolRes](ctx, z.c, OpZFSExists, nameArgs{name}, callOpts{})
	return r.V, err
}
func (z zfsClient) Set(ctx context.Context, name string, props map[string]string) error {
	return callNone(ctx, z.c, OpZFSSet, zfsSetArgs{name, props})
}
func (z zfsClient) Inherit(ctx context.Context, name string, props ...string) error {
	return callNone(ctx, z.c, OpZFSInherit, zfsGetArgs{name, props})
}
func (z zfsClient) Create(ctx context.Context, o zfs.CreateOpts) error {
	return callNone(ctx, z.c, OpZFSCreate, o)
}
func (z zfsClient) Clone(ctx context.Context, snapshot, target string, props map[string]string, parents bool) error {
	return callNone(ctx, z.c, OpZFSClone, zfsCloneArgs{snapshot, target, props, parents})
}
func (z zfsClient) Snapshot(ctx context.Context, o zfs.SnapshotOpts) error {
	return callNone(ctx, z.c, OpZFSSnapshot, o)
}
func (z zfsClient) Destroy(ctx context.Context, name string, o zfs.DestroyOpts) error {
	return callNone(ctx, z.c, OpZFSDestroy, zfsDestroyArgs{name, o})
}
func (z zfsClient) Rename(ctx context.Context, from, to string, o zfs.RenameOpts) error {
	return callNone(ctx, z.c, OpZFSRename, zfsRenameArgs{from, to, o})
}
func (z zfsClient) Rollback(ctx context.Context, snapshot string, o zfs.RollbackOpts) error {
	return callNone(ctx, z.c, OpZFSRollback, zfsRollbackArgs{snapshot, o})
}
func (z zfsClient) Hold(ctx context.Context, tag string, snapshots ...string) error {
	return callNone(ctx, z.c, OpZFSHold, zfsHoldArgs{tag, snapshots})
}
func (z zfsClient) Release(ctx context.Context, tag string, snapshots ...string) error {
	return callNone(ctx, z.c, OpZFSRelease, zfsHoldArgs{tag, snapshots})
}
func (z zfsClient) Holds(ctx context.Context, snapshot string) ([]zfs.Hold, error) {
	return callJSON[[]zfs.Hold](ctx, z.c, OpZFSHolds, nameArgs{snapshot}, callOpts{})
}
func (z zfsClient) Bookmark(ctx context.Context, snapshot, bookmark string) error {
	return callNone(ctx, z.c, OpZFSBookmark, zfsBookmarkArgs{snapshot, bookmark})
}
func (z zfsClient) Written(ctx context.Context, dataset, since string) (uint64, error) {
	r, err := callJSON[guidRes](ctx, z.c, OpZFSWritten, zfsWrittenArgs{dataset, since}, callOpts{})
	return r.V, err
}
func (z zfsClient) GUID(ctx context.Context, name string) (uint64, error) {
	r, err := callJSON[guidRes](ctx, z.c, OpZFSGUID, nameArgs{name}, callOpts{})
	return r.V, err
}
func (z zfsClient) Clones(ctx context.Context, snapshot string) ([]string, error) {
	r, err := callJSON[strsRes](ctx, z.c, OpZFSClones, nameArgs{snapshot}, callOpts{})
	return r.V, err
}
func (z zfsClient) Origin(ctx context.Context, dataset string) (string, error) {
	r, err := callJSON[strRes](ctx, z.c, OpZFSOrigin, nameArgs{dataset}, callOpts{})
	return r.V, err
}

// Send streams the send stream into w; cancel ctx to abort.
func (z zfsClient) Send(ctx context.Context, o zfs.SendOpts, w io.Writer) error {
	_, err := callJSON[empty](ctx, z.c, OpZFSSend, o, callOpts{out: w})
	return err
}

// Receive streams r into zfs receive; cancel ctx to abort.
func (z zfsClient) Receive(ctx context.Context, o zfs.ReceiveOpts, r io.Reader) error {
	_, err := callJSON[empty](ctx, z.c, OpZFSReceive, o, callOpts{in: r, fill: true})
	return err
}

// Replicate copies a snapshot into a new dataset; the stream goes from zfs send to zfs receive inside the helper.
func (z zfsClient) Replicate(ctx context.Context, snapshot, dst string, props map[string]string) error {
	return callNone(ctx, z.c, OpZFSReplicate, zfsReplicateArgs{Snapshot: snapshot, Dst: dst, Props: props})
}
func (z zfsClient) ReceiveAbort(ctx context.Context, dataset string) error {
	return callNone(ctx, z.c, OpZFSReceiveAbort, nameArgs{dataset})
}
func (z zfsClient) ListPools(ctx context.Context) ([]zfs.Pool, error) {
	return callJSON[[]zfs.Pool](ctx, z.c, OpZFSListPools, empty{}, callOpts{})
}
func (z zfsClient) ActiveFeatures(ctx context.Context, pool string) ([]string, error) {
	r, err := callJSON[strsRes](ctx, z.c, OpZFSActiveFeatures, nameArgs{pool}, callOpts{})
	return r.V, err
}

// ---- jails ----

type jailClient struct{ c *Client }

var _ jailos.Jails = jailClient{}

func (j jailClient) List(ctx context.Context) ([]jailos.Jail, error) {
	return callJSON[[]jailos.Jail](ctx, j.c, OpJailList, empty{}, callOpts{})
}
func (j jailClient) Get(ctx context.Context, name string) (jailos.Jail, bool, error) {
	r, err := callJSON[jailGetRes](ctx, j.c, OpJailGet, nameArgs{name}, callOpts{})
	return r.Jail, r.Found, err
}
func (j jailClient) Create(ctx context.Context, confPath, name string) error {
	return callNone(ctx, j.c, OpJailCreate, jailConfArgs{confPath, name})
}
func (j jailClient) Remove(ctx context.Context, confPath, name string) error {
	return callNone(ctx, j.c, OpJailRemove, jailConfArgs{confPath, name})
}
func (j jailClient) Exec(ctx context.Context, name string, o jailos.ExecOpts) (run.Result, error) {
	args := execArgs{Name: name, Argv: o.Argv, User: o.User, Login: o.Login, Stdin: o.Stdin != nil}
	if o.Timeout > 0 {
		args.TimeoutMs = o.Timeout.Milliseconds()
	}
	return j.c.exec(ctx, OpJailExec, args, o.Stdin, o.Stdout, 0)
}

// ---- pf ----

type pfClient struct{ c *Client }

var _ pfctl.Client = pfClient{}

func (p pfClient) Validate(ctx context.Context, anchor, ruleset string) (string, error) {
	r, err := callJSON[strRes](ctx, p.c, OpPFValidate, pfArgs{Anchor: anchor, Ruleset: ruleset}, callOpts{})
	return r.V, err
}
func (p pfClient) Load(ctx context.Context, anchor, ruleset string) error {
	return callNone(ctx, p.c, OpPFLoad, pfArgs{Anchor: anchor, Ruleset: ruleset})
}
func (p pfClient) Read(ctx context.Context, anchor string) (string, error) {
	r, err := callJSON[strRes](ctx, p.c, OpPFRead, pfArgs{Anchor: anchor}, callOpts{})
	return r.V, err
}
func (p pfClient) Flush(ctx context.Context, anchor string) error {
	return callNone(ctx, p.c, OpPFFlush, pfArgs{Anchor: anchor})
}
func (p pfClient) TableAdd(ctx context.Context, anchor, table string, addrs ...string) error {
	return callNone(ctx, p.c, OpPFTableAdd, pfArgs{Anchor: anchor, Table: table, Addrs: addrs})
}
func (p pfClient) TableDelete(ctx context.Context, anchor, table string, addrs ...string) error {
	return callNone(ctx, p.c, OpPFTableDelete, pfArgs{Anchor: anchor, Table: table, Addrs: addrs})
}
func (p pfClient) KillLabel(ctx context.Context, label string) error {
	return callNone(ctx, p.c, OpPFKillLabel, pfArgs{Label: label})
}
func (p pfClient) TableShow(ctx context.Context, anchor, table string) ([]string, error) {
	r, err := callJSON[strsRes](ctx, p.c, OpPFTableShow, pfArgs{Anchor: anchor, Table: table}, callOpts{})
	return r.V, err
}

// ---- interfaces ----

type netClient struct{ c *Client }

var _ ifconfig.Client = netClient{}

func (n netClient) List(ctx context.Context) ([]ifconfig.Iface, error) {
	return callJSON[[]ifconfig.Iface](ctx, n.c, OpNetList, empty{}, callOpts{})
}
func (n netClient) SetDescription(ctx context.Context, iface, desc string) error {
	return callNone(ctx, n.c, OpNetSetDescription, netArgs{Iface: iface, Desc: desc})
}
func (n netClient) EpairCreate(ctx context.Context, name string) (string, string, error) {
	r, err := callJSON[epairRes](ctx, n.c, OpNetEpairCreate, netArgs{Name: name}, callOpts{})
	return r.A, r.B, err
}
func (n netClient) EpairDestroy(ctx context.Context, iface string) error {
	return callNone(ctx, n.c, OpNetEpairDestroy, netArgs{Iface: iface})
}
func (n netClient) MoveToJail(ctx context.Context, iface, jail string) error {
	return callNone(ctx, n.c, OpNetMoveToJail, netArgs{Iface: iface, Jail: jail})
}
func (n netClient) MoveFromJail(ctx context.Context, iface, jail string) error {
	return callNone(ctx, n.c, OpNetMoveFromJail, netArgs{Iface: iface, Jail: jail})
}
func (n netClient) SetLink(ctx context.Context, iface string, up bool) error {
	return callNone(ctx, n.c, OpNetSetLink, netArgs{Iface: iface, Up: up})
}
func (n netClient) AddrAdd(ctx context.Context, iface string, p netip.Prefix) error {
	return callNone(ctx, n.c, OpNetAddrAdd, netArgs{Iface: iface, Prefix: p})
}
func (n netClient) AddrRemove(ctx context.Context, iface string, p netip.Prefix) error {
	return callNone(ctx, n.c, OpNetAddrRemove, netArgs{Iface: iface, Prefix: p})
}
func (n netClient) RouteAdd(ctx context.Context, r ifconfig.Route) error {
	return callNone(ctx, n.c, OpNetRouteAdd, netArgs{Route: r})
}
func (n netClient) RouteDelete(ctx context.Context, r ifconfig.Route) error {
	return callNone(ctx, n.c, OpNetRouteDelete, netArgs{Route: r})
}
func (n netClient) IPv6Forwarding(ctx context.Context) (bool, error) {
	r, err := callJSON[boolRes](ctx, n.c, OpNetIPv6Forwarding, empty{}, callOpts{})
	return r.V, err
}
