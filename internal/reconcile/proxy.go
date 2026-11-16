package reconcile

import (
	"context"
	"fmt"
	"jailops.net/jailops/internal/supervise"
	"net/netip"
	"time"

	"jailops.net/jailops/internal/ndproxy"
	"jailops.net/jailops/sdk/api"
)

type proxyHandle struct {
	ndp    NDP
	cancel context.CancelFunc
	done   chan struct{}
	err    error
}

// proxyPass keeps one neighbor discovery proxy per uplink in step with the
// addresses of running jails on proxy-mode networks. A proxy-mode network always has one; what a daemon may do on
// the uplink is the operator's decision in the helper's configuration, and the network says so when it is refused.
// Routed IPv6 never depends on it.
func (r *Reconciler) proxyPass(ctx context.Context, des Desired, obs *Observed, netStatus map[string]*api.NetworkStatus, rep *Report, now time.Time) {
	proxyNets := map[string]bool{} // networks in proxy mode
	for _, n := range des.Networks {
		if n.Spec.IPv6 != nil && n.Spec.IPv6.Mode == api.IPv6Proxy {
			proxyNets[n.Name] = true
		}
	}
	if len(proxyNets) == 0 && len(r.proxies) == 0 {
		return
	}
	setCond := func(network string, ok bool, reason, msg string) {
		if st := netStatus[network]; st != nil {
			st.Conditions = append(st.Conditions, cond(CondProxy, ok, reason, msg, now))
		}
	}
	if r.cfg.NDP == nil {
		for n := range proxyNets {
			setCond(n, false, "Unsupported", "no neighbor discovery proxy is available on this daemon")
		}
		return
	}
	byUplink := map[string][]ndproxy.Entry{}
	uplinkNets := map[string][]string{} // uplink -> the proxy-mode networks that use it
	for _, j := range des.Jails {
		if _, up := obs.Running[j.Name]; !up {
			continue
		}
		for _, p := range j.Proxy {
			a, err := netip.ParseAddr(p.Addr)
			if err != nil {
				continue
			}
			byUplink[p.Uplink] = append(byUplink[p.Uplink], ndproxy.Entry{Addr: a, Iface: p.Iface})
		}
	}
	for _, n := range des.Networks {
		if n.Spec.IPv6 != nil && n.Spec.IPv6.Mode == api.IPv6Proxy && n.Spec.Uplink != "" {
			uplinkNets[n.Spec.Uplink] = append(uplinkNets[n.Spec.Uplink], n.Name)
			if _, ok := byUplink[n.Spec.Uplink]; !ok {
				byUplink[n.Spec.Uplink] = nil
			}
		}
	}
	for uplink, entries := range byUplink {
		h := r.proxies[uplink]
		if h == nil {
			ndp, err := r.cfg.NDP(uplink)
			if err != nil {
				for _, b := range uplinkNets[uplink] {
					setCond(b, false, "StartFailed", err.Error())
				}
				rep.Failures["ndproxy/"+uplink] = err.Error()
				continue
			}
			pctx, cancel := context.WithCancel(context.WithoutCancel(ctx))
			h = &proxyHandle{ndp: ndp, cancel: cancel, done: make(chan struct{})}
			go func() {
				defer close(h.done)
				if err := supervise.Guard(r.log, "ndproxy", func() { h.err = ndp.Run(pctx) }); err != nil {
					h.err = err
				}
			}()
			r.proxies[uplink] = h
			// The capture opens in the proxy's own goroutine, a moment from now; the condition below says "Starting"
			// for this pass. Without another look it would say so until the next pass, a whole interval later.
			r.Kick()
		}
		select {
		case <-h.done:
			msg := "the proxy stopped"
			if h.err != nil {
				msg = h.err.Error()
			}
			_ = h.ndp.Close()
			delete(r.proxies, uplink)
			for _, b := range uplinkNets[uplink] {
				setCond(b, false, "Stopped", msg)
			}
			rep.Failures["ndproxy/"+uplink] = msg
			continue
		default:
		}
		if err := h.ndp.Sync(ctx, entries); err != nil {
			for _, b := range uplinkNets[uplink] {
				setCond(b, false, "SyncFailed", err.Error())
			}
			rep.Failures["ndproxy/"+uplink] = err.Error()
			continue
		}
		// Sync only changes the table: the proxy answers only while its capture is open.
		st := h.ndp.Status()
		if !st.Open {
			reason, msg := "Starting", "the capture of "+uplink+" is being opened"
			if st.Err != "" {
				reason, msg = "NoCapture", "the capture of "+uplink+" cannot be opened: "+st.Err
				rep.Failures["ndproxy/"+uplink] = msg
			}
			for _, b := range uplinkNets[uplink] {
				setCond(b, false, reason, msg)
			}
			continue
		}
		for _, b := range uplinkNets[uplink] {
			setCond(b, true, "Answering", fmt.Sprintf("answering for %d address(es) on %s", len(entries), uplink))
			if st.FloodsLastHour > 0 {
				if ns := netStatus[b]; ns != nil {
					ns.Conditions = append(ns.Conditions, cond(CondProxyFlood, false, "Flooded",
						fmt.Sprintf("%d solicitation(s) on %s were dropped over the proxy's limits in the last hour", st.FloodsLastHour, uplink), now))
				}
			}
		}
	}
	// Uplinks nobody needs any more.
	for uplink, h := range r.proxies {
		if _, ok := byUplink[uplink]; !ok {
			_ = h.ndp.Sync(ctx, nil)
			h.cancel()
			go func(h *proxyHandle) { <-h.done; _ = h.ndp.Close() }(h)
			delete(r.proxies, uplink)
		}
	}
}

func (r *Reconciler) stopProxies() {
	for k, h := range r.proxies {
		_ = h.ndp.Sync(context.Background(), nil)
		h.cancel()
		<-h.done
		_ = h.ndp.Close()
		delete(r.proxies, k)
	}
}

// Close stops the proxies (Run does it on exit; tests that call Pass call this).
func (r *Reconciler) Close() { r.passMu.Lock(); defer r.passMu.Unlock(); r.stopProxies() }
