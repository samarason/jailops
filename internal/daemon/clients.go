package daemon

import (
	"context"
	"fmt"
	"io"
	"net"
	"time"

	"jailops.net/jailops/internal/lifecycle"
	"jailops.net/jailops/internal/priv"
	"jailops.net/jailops/internal/service"
	"jailops.net/jailops/internal/service/zfsadapt"
	"jailops.net/jailops/internal/sys/ifconfig"
	"jailops.net/jailops/internal/sys/jailos"
	"jailops.net/jailops/internal/sys/pfctl"
	"jailops.net/jailops/internal/sys/run"
	"jailops.net/jailops/internal/sys/zfs"
	"jailops.net/jailops/internal/wireguard"
)

// Clients is everything jailopsd needs from the operating system. In
// production it is backed by jailops-priv over its socket; tests build it from
// fakes.
type Clients struct {
	ZFS    zfs.Client
	Jails  jailos.Jails
	PF     pfctl.Client
	Net    ifconfig.Client
	Runner run.Runner
	Files  service.FS
	// Logs reads jail log files (the helper in production, see service.LogReader).
	Logs    service.LogReader
	Sysctl  func(ctx context.Context, name string) (string, error)
	Mount   func(ctx context.Context, dataset string) error
	Unmount func(ctx context.Context, dataset string) error
	// Dial connects from the host to a jail (the health checks of an app
	// installation); nil uses the network.
	Dial func(ctx context.Context, network, address string) (net.Conn, error)
	// HostFile reads a world-readable file of the host as the daemon (nil: the file system; tests: the simulated host).
	HostFile func(path string) ([]byte, error)
	// Host is the helper (nil in tests); the NDP proxy opens BPF through it.
	Host priv.Host
	// HostSystem changes the host itself (host management; the helper in production, nil: unsupported).
	HostSystem service.HostSystem
	// WG configures WireGuard interfaces (the helper; nil means unsupported).
	WG wireguard.Host
	// Keys handles encrypted volumes (the helper; nil means unsupported).
	Keys lifecycle.Keys
	// Closer releases the connection.
	Closer io.Closer
}

// ClientFactory builds Clients. It is injectable so tests and alternative
// deployments replace it.
type ClientFactory func(ctx context.Context, cfg *Config, dev bool) (*Clients, error)

func fromHost(h priv.Host, files service.FS) *Clients {
	return &Clients{ZFS: h.ZFS(), Jails: h.Jails(), PF: h.PF(), Net: h.Net(), Runner: h.Runner(), Files: files, Logs: h,
		Sysctl: h.Sysctl, Mount: h.Mount, Unmount: h.Unmount, Host: h, HostSystem: h, WG: h, Keys: &zfsadapt.Keys{H: h, C: h.ZFS()}}
}

func privConfig(cfg *Config) priv.Config {
	return priv.Config{RootDataset: cfg.Dataset, MountBase: cfg.MountBase, ConfDir: cfg.ConfDir, StateDir: cfg.StateDir, WorkDir: cfg.WorkDir}
}

// PrivConnectWait is how long the daemon waits for the helper's socket to appear when it starts.
var PrivConnectWait = 30 * time.Second

// DefaultClients connects to jailops-priv. With dev it runs the helper's
// operations in process, which needs root: that is for development only.
func DefaultClients(ctx context.Context, cfg *Config, dev bool) (*Clients, error) {
	if dev {
		l, err := priv.NewSystem(privConfig(cfg))
		if err != nil {
			return nil, fmt.Errorf("dev mode: %w", err)
		}
		return fromHost(l, osFiles{}), nil
	}
	// The helper's rc script returns before its socket exists (and a restart of both services starts them together),
	// so the first connection is retried for a while before it is called a failure.
	var c *priv.Client
	var err error
	for deadline := time.Now().Add(PrivConnectWait); ; {
		if c, err = priv.Dial(cfg.Priv.Socket); err == nil || time.Now().After(deadline) || ctx.Err() != nil {
			break
		}
		time.Sleep(250 * time.Millisecond)
	}
	if err != nil {
		return nil, fmt.Errorf("cannot reach jailops-priv at %s: %w", cfg.Priv.Socket, err)
	}
	cl := fromHost(c, privFiles{h: c, own: cfg.StateDir})
	cl.Closer = c
	return cl, nil
}
