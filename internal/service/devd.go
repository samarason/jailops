package service

import (
	"context"
	"sync"

	"jailops.net/jailops/internal/devd"
	"jailops.net/jailops/internal/validate"
	"jailops.net/jailops/sdk/api"
)

// devdHolder keeps the watcher of the kernel's notifications, so that doctor can say whether it is connected.
type devdHolder struct {
	mu sync.Mutex
	w  *devd.Watcher
}

func (h *devdHolder) set(w *devd.Watcher) {
	h.mu.Lock()
	h.w = w
	h.mu.Unlock()
}

func (h *devdHolder) get() *devd.Watcher {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.w
}

// RunDevd reads the notifications of devd(8) from the socket at path until ctx ends and publishes the ones an operator
// acts on as events: a ZFS error or a change of a pool, the link of the uplink, and a resource
// limit that a jail hit. A host without devd, or a socket the daemon cannot read, is retried slowly and shows in doctor.
func (s *Service) RunDevd(ctx context.Context, path string) {
	w := devd.New(devd.Config{
		Path: path, Log: s.log, Now: s.now,
		Mapper: devd.Mapper{Link: s.devdLink, Jail: s.devdJail},
		Sink: func(ev devd.Event) {
			s.events.publish(api.EventLifecycle, api.LifecycleEvent{Action: ev.Action, Source: ev.Source, Requestor: "devd", Project: ev.Project, Detail: ev.Detail}, s.now())
		},
	})
	s.devdState.set(w)
	w.Run(ctx)
}

// devdLink says what an interface is when it is the uplink of a network. The epairs of
// the jails are left out: their ends change state with every start and stop.
func (s *Service) devdLink(iface string) (string, bool) {
	nets, err := s.netKind.list()
	if err != nil {
		return "", false
	}
	for _, n := range nets {
		if n.Spec.Uplink != "" && n.Spec.Uplink == iface {
			return "uplink " + iface, true
		}
	}
	return "", false
}

// devdJail resolves the name the kernel knows a jail by to its project and name, for a jail JailOps manages.
func (s *Service) devdJail(osName string) (project, name string, ok bool) {
	if _, err := s.jailSnapshot(osName); err != nil {
		return "", "", false
	}
	project, name = validate.SplitQualified(osName)
	return project, name, project != ""
}

func (s *Service) doctorDevd(c *checkSet) {
	w := s.devdState.get()
	if w == nil {
		return
	}
	if st := w.Status(); st.Connected {
		c.add("host.devd", api.DoctorOK, "reading kernel events from devd ("+w.Path()+")", "")
	} else {
		c.add("host.devd", api.DoctorWarn, "cannot read devd at "+w.Path()+": "+st.Err,
			"ZFS errors, link changes and limits hit by jails are not shown as events; is devd running, and may the daemon read the socket? devd.enable: false in jailopsd.yaml turns this off")
	}
}
