package service

import (
	"context"
	"net/netip"
	"slices"
	"strings"
	"time"

	"jailops.net/jailops/sdk/api"
)

// Host management, module firewall (docs/appliance.md): the host's /etc/pf.conf, rendered whole by the helper from
// a validated spec, and commit confirmed, the confirmation window every firewall change goes through. The timer of
// the window lives in the helper, never here: the daemon only reads the pending record and passes a confirmation or
// a revert on.

// HostFirewallSystem is the privileged side of the firewall module and of commit confirmed.
type HostFirewallSystem interface {
	// HostFirewallRead reads the state of /etc/pf.conf and pf. It changes nothing and needs no admin assertion.
	HostFirewallRead(ctx context.Context) (HostFirewallState, error)
	// HostFirewallApply renders, checks and loads a firewall, or with DryRun only says what it would do.
	HostFirewallApply(ctx context.Context, q HostFirewallRequest) (api.HostChange, error)
	// HostPending reads the pending change and the outcome of the last one.
	HostPending(ctx context.Context) (api.HostPending, error)
	// HostPendingConfirm keeps the pending change; HostPendingRevert puts its snapshot back now. id "" means
	// whichever change is pending.
	HostPendingConfirm(ctx context.Context, id string) (api.HostPending, error)
	HostPendingRevert(ctx context.Context, id string) (api.HostPending, error)
}

// HostFirewallRequest is what the daemon asks the helper to apply.
type HostFirewallRequest struct {
	Spec   api.HostFirewallSpec `json:"spec"`
	DryRun bool                 `json:"dry_run,omitempty"`
	// ConfirmWithin is the confirmation window in seconds (0: the default).
	ConfirmWithin int `json:"confirm_within,omitempty"`
	// Peer is the address the request came from, as the daemon's listener saw it; empty when it is unknown (the
	// unix socket, a hub). The lock-out check uses it.
	Peer           string `json:"peer,omitempty"`
	ConfirmLockout bool   `json:"confirm_lockout,omitempty"`
}

// HostFirewallState is what the helper reads.
type HostFirewallState struct {
	FileExists  bool `json:"file_exists,omitempty"`
	FileManaged bool `json:"file_managed,omitempty"`
	// Drift names what changed since the last apply ("pf.conf", "pf_enable", "pf_rules").
	Drift     []string              `json:"drift,omitempty"`
	Applied   *api.HostFirewallSpec `json:"applied,omitempty"`
	AppliedAt time.Time             `json:"applied_at,omitzero"`
	// PFEnabled is nil when pfctl could not be asked.
	PFEnabled *bool                  `json:"pf_enabled,omitempty"`
	Pending   *api.HostPendingChange `json:"pending,omitempty"`
	// Modules are the modules priv.conf lets the helper change.
	Modules []string `json:"modules,omitempty"`
	// StatePolicyIfBound says whether /etc/pf.conf has `set state-policy if-bound`; the helper (root) reads the file,
	// which the daemon often cannot (mode 0600). Nil when there is no such file.
	StatePolicyIfBound *bool `json:"state_policy_if_bound,omitempty"`
}

// PFBindsStates says whether the text of a pf.conf has `set state-policy if-bound` (comments do not count).
func PFBindsStates(text string) bool { return reStatePolicy.MatchString(stripPFComments(text)) }

func (s *Service) hostFirewallSystem() (HostFirewallSystem, error) {
	if _, err := s.hostSystem(); err != nil {
		return nil, err
	}
	fw, ok := s.d.Host.(HostFirewallSystem)
	if !ok {
		return nil, api.Errorf(api.CodeUnsupported, "the privileged helper of this daemon has no firewall module").
			WithHint("update jailops-priv to the version of jailopsd")
	}
	return fw, nil
}

// HostFirewall reads the host's firewall and how JailOps manages it. It works whether the module is enabled or not.
func (s *Service) HostFirewall(ctx context.Context) (api.HostFirewall, error) {
	if err := requireGlobal(ctx, "reading the host firewall"); err != nil {
		return api.HostFirewall{}, err
	}
	fw, err := s.hostFirewallSystem()
	if err != nil {
		return api.HostFirewall{}, err
	}
	st, err := fw.HostFirewallRead(ctx)
	if err != nil {
		return api.HostFirewall{}, err
	}
	return s.hostFirewallView(st), nil
}

func (s *Service) hostFirewallView(st HostFirewallState) api.HostFirewall {
	spec := api.DefaultHostFirewall(s.d.ConsolePort)
	spec.ACME = s.acmeRedirect()
	if st.Applied != nil {
		spec = *st.Applied
	}
	cfg, helper := s.hostConfigured(api.HostModuleFirewall), slices.Contains(st.Modules, api.HostModuleFirewall)
	out := api.HostFirewall{Kind: api.KindHostFirewall, Spec: spec, Status: api.HostFirewallStatus{
		Managed: cfg && helper, ConfigEnabled: cfg, HelperEnabled: helper, FileExists: st.FileExists, FileManaged: st.FileManaged,
		Drift: st.Drift, Applied: st.Applied, PFEnabled: st.PFEnabled, Rules: spec.Rules(), Pending: st.Pending, ConsolePort: s.d.ConsolePort,
	}}
	if st.Applied != nil && !st.AppliedAt.IsZero() {
		t := st.AppliedAt.UTC()
		out.Status.AppliedAt = &t
	}
	if out.Status.Managed || st.Applied != nil {
		out.Status.Warnings = spec.Warnings()
	}
	return out
}

// acmeRedirect is the challenge redirect the certificate needs, nil without ACME.
func (s *Service) acmeRedirect() *api.HostFirewallACME {
	if s.d.Certificates == nil {
		return nil
	}
	return s.d.Certificates.Redirect()
}

// peerOf is the address of the caller as the listener saw it; unknown for the unix socket and through a hub (the
// hub's address says nothing about the person behind it).
func peerOf(ctx context.Context) string {
	a := ActorFrom(ctx)
	if a.Kind == "hub" || a.Kind == "unix" || a.Kind == "system" {
		return ""
	}
	if ip, err := netip.ParseAddr(a.Remote); err == nil {
		return ip.Unmap().WithZone("").String()
	}
	return ""
}

// ApplyHostFirewall renders and loads the host firewall with a confirmation window, or with DryRun says what it
// would change.
func (s *Service) ApplyHostFirewall(ctx context.Context, in api.HostFirewallApply) (api.HostChange, error) {
	spec := in.Spec
	if spec.Console != nil && spec.Console.Port != 0 && spec.Console.Port != s.d.ConsolePort {
		return api.HostChange{}, api.Errorf(api.CodeInvalid, "console port %d is not the daemon's port (%d)", spec.Console.Port, s.d.ConsolePort).
			WithHint("leave console.port out: the daemon fills in the port of listen.https.address")
	}
	if spec.Console == nil {
		spec.Console = &api.HostFirewallConsole{}
	} else {
		c := *spec.Console
		spec.Console = &c
	}
	spec.Console.Port = s.d.ConsolePort
	// the redirect of an ACME challenge is the daemon's to fill in: what a client sends is replaced
	spec.ACME = s.acmeRedirect()
	if err := spec.Validate(); err != nil {
		return api.HostChange{}, err
	}
	if _, err := api.ConfirmWindow(in.ConfirmWithin); err != nil {
		return api.HostChange{}, err
	}
	if _, err := s.hostChangeAllowed(ctx, api.HostModuleFirewall, "changing the host firewall"); err != nil {
		return api.HostChange{}, err
	}
	fw, err := s.hostFirewallSystem()
	if err != nil {
		return api.HostChange{}, err
	}
	unlock, err := s.locks.tryLock("host firewall", "host/firewall")
	if err != nil {
		return api.HostChange{}, err
	}
	defer unlock()
	res, err := fw.HostFirewallApply(ctx, HostFirewallRequest{Spec: spec.Canonical(), DryRun: in.DryRun, ConfirmWithin: in.ConfirmWithin, Peer: peerOf(ctx), ConfirmLockout: in.ConfirmLockout})
	if err != nil {
		return api.HostChange{}, notManagedByHelper(err, api.HostModuleFirewall)
	}
	if res.Actions == nil {
		res.Actions = []string{}
	}
	if !in.DryRun && res.Changed {
		s.emit(ctx, "host-firewall-updated", "/api/v1/host/firewall")
	}
	return res, nil
}

// HostPending says which change waits for its confirmation, and how the last one ended.
func (s *Service) HostPending(ctx context.Context) (api.HostPending, error) {
	if err := requireGlobal(ctx, "reading the pending host change"); err != nil {
		return api.HostPending{}, err
	}
	fw, err := s.hostFirewallSystem()
	if err != nil {
		return api.HostPending{}, err
	}
	return fw.HostPending(ctx)
}

// ConfirmHostPending keeps the pending change. Coming through the new configuration, the request proves that the
// administrator can still reach the host.
func (s *Service) ConfirmHostPending(ctx context.Context, in api.HostPendingAction) (api.HostPending, error) {
	return s.hostPendingAction(ctx, in, "confirming a host change", true)
}

// RevertHostPending puts the snapshot of the pending change back now.
func (s *Service) RevertHostPending(ctx context.Context, in api.HostPendingAction) (api.HostPending, error) {
	return s.hostPendingAction(ctx, in, "reverting a host change", false)
}

func (s *Service) hostPendingAction(ctx context.Context, in api.HostPendingAction, what string, confirm bool) (api.HostPending, error) {
	if err := api.ValidHostPendingID(in.ID); err != nil {
		return api.HostPending{}, err
	}
	if err := requireGlobal(ctx, what); err != nil {
		return api.HostPending{}, err
	}
	if a := ActorFrom(ctx); a.Perm != api.PermAdmin {
		return api.HostPending{}, api.Errorf(api.CodeForbidden, "%s needs the admin role", what)
	}
	fw, err := s.hostFirewallSystem()
	if err != nil {
		return api.HostPending{}, err
	}
	var res api.HostPending
	if confirm {
		res, err = fw.HostPendingConfirm(ctx, in.ID)
	} else {
		res, err = fw.HostPendingRevert(ctx, in.ID)
	}
	if err != nil {
		return api.HostPending{}, err
	}
	if res.Last != nil {
		s.emit(ctx, "host-change-"+strings.ReplaceAll(res.Last.Outcome, "_", "-"), "/api/v1/host/pending")
	}
	return res, nil
}

// doctorHostFirewall reports the firewall module (host.firewall): drift and a change waiting for its confirmation.
func (s *Service) doctorHostFirewall(ctx context.Context, c *checkSet) {
	fw, ok := s.d.Host.(HostFirewallSystem)
	if s.d.Host == nil || !ok {
		return
	}
	st, err := fw.HostFirewallRead(ctx)
	if err != nil {
		c.add("host.firewall", api.DoctorUnknown, "cannot read the host firewall: "+err.Error(), "")
		return
	}
	v := s.hostFirewallView(st)
	switch {
	case !v.Status.Managed && v.Status.ConfigEnabled != v.Status.HelperEnabled:
		c.add("host.firewall", api.DoctorWarn, "enabled in only one of jailopsd.yaml and priv.conf, so not managed",
			hostManageHint(api.HostModuleFirewall, v.Status.ConfigEnabled, v.Status.HelperEnabled))
	case !v.Status.Managed:
		c.add("host.firewall", api.DoctorOK, "not managed by JailOps (/etc/pf.conf is the administrator's)", "")
	case st.Pending != nil:
		c.add("host.firewall", api.DoctorWarn, "a "+st.Pending.Module+" change waits for its confirmation and reverts at "+st.Pending.Deadline.UTC().Format(time.RFC3339),
			"confirm it with `jailops host confirm`, or undo it now with `jailops host revert`")
	case len(v.Status.Drift) > 0:
		c.add("host.firewall", api.DoctorWarn, "changed outside JailOps since it was applied: "+strings.Join(v.Status.Drift, ", "),
			"see the difference with `jailops host firewall diff`; apply again with `jailops host firewall apply`, or put a copy back with `jailops host restore`")
	case v.Status.Applied == nil:
		c.add("host.firewall", api.DoctorOK, "managed by JailOps; nothing applied yet (/etc/pf.conf is still the administrator's)", "")
	default:
		c.add("host.firewall", api.DoctorOK, "managed by JailOps; /etc/pf.conf is what was applied", "")
	}
}
