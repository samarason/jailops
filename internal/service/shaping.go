package service

import (
	"context"
	"encoding/json"
	"fmt"
	"maps"
	"path"
	"sort"
	"strconv"
	"strings"
	"sync"

	"jailops.net/jailops/internal/reconcile"
	"jailops.net/jailops/internal/render"
	"jailops.net/jailops/internal/sys/run"
	"jailops.net/jailops/internal/validate"
	"jailops.net/jailops/sdk/api"
)

// DummynetModule is the kernel module whose pipes carry the bandwidth limits.
const DummynetModule = "dummynet"

// shapedDevice is one direction of one device of a jail with a bandwidth limit: nic.<device>.egress or
// nic.<device>.ingress, in bits per second.
type shapedDevice struct {
	key  render.PipeKey
	rate uint64
}

// shapedDevices lists every direction of every device of every jail that has a bandwidth limit, from the specs the
// jails have now (with their profiles merged). A limit that does not parse is skipped here; the spec validation
// refuses it when it is set.
func (s *Service) shapedDevices() []shapedDevice {
	s.mu.RLock()
	names := sortedKeys(s.jails)
	jails := make([]api.Jail, 0, len(names))
	for _, n := range names {
		jails = append(jails, s.jails[n].jail)
	}
	s.mu.RUnlock()
	var out []shapedDevice
	for _, j := range jails {
		for i, nd := range s.effective(j).Network {
			for _, dir := range []struct {
				limit   string
				ingress bool
			}{{nd.Egress, false}, {nd.Ingress, true}} {
				if dir.limit == "" {
					continue
				}
				bits, err := validate.ParseRate(dir.limit)
				if err != nil || bits == 0 {
					continue
				}
				out = append(out, shapedDevice{key: render.PipeKey{Jail: j.Metadata.UUID, Device: i, Ingress: dir.ingress}, rate: bits})
			}
		}
	}
	return out
}

// pipeTable is the pipe number of every limited direction of a device, kept on disk: a number is given once, when a
// limit is first set, and stays with its device until the limit is removed (render.AllocatePipes), so the anchors and
// the states of other jails never see a pipe renumbered.
type pipeTable struct {
	mu     sync.Mutex
	loaded bool
	nums   map[render.PipeKey]int
}

// pipeTableFile is where the table is kept.
func (s *Service) pipeTableFile() string { return path.Join(s.d.StateDir, "rendered", "pipes.json") }

type pipeEntry struct {
	Jail    string `json:"jail"`
	Device  int    `json:"device"`
	Ingress bool   `json:"ingress,omitempty"`
	Pipe    int    `json:"pipe"`
}

// loadPipes reads the table from disk once.
func (s *Service) loadPipes(ctx context.Context) {
	t := &s.pipes
	if t.loaded {
		return
	}
	t.loaded = true
	t.nums = map[render.PipeKey]int{}
	if s.d.StateDir == "" || s.d.Files == nil {
		return
	}
	b, err := s.d.Files.ReadFile(ctx, s.pipeTableFile())
	if err != nil {
		return
	}
	var es []pipeEntry
	if json.Unmarshal(b, &es) != nil {
		return
	}
	for _, e := range es {
		t.nums[render.PipeKey{Jail: e.Jail, Device: e.Device, Ingress: e.Ingress}] = e.Pipe
	}
}

// savePipes writes the table after it changed. A table that cannot be saved is an error: the numbers of other jails
// could be allocated again at the next start, and a jail's traffic would run through another jail's pipe.
func (s *Service) savePipes(ctx context.Context) error {
	if s.d.StateDir == "" || s.d.Files == nil {
		return nil
	}
	var es []pipeEntry
	for k, n := range s.pipes.nums {
		es = append(es, pipeEntry{Jail: k.Jail, Device: k.Device, Ingress: k.Ingress, Pipe: n})
	}
	sort.Slice(es, func(i, j int) bool { return es[i].Pipe < es[j].Pipe })
	b, err := json.Marshal(es)
	if err != nil {
		return err
	}
	p := s.pipeTableFile()
	if err := s.d.Files.MkdirAll(ctx, path.Dir(p)); err != nil {
		return fmt.Errorf("saving the dummynet pipe numbers: %w", err)
	}
	if err := s.d.Files.WriteAtomic(ctx, p, b); err != nil {
		return fmt.Errorf("saving the dummynet pipe numbers: %w", err)
	}
	return nil
}

// shapingPlan gives the pipe number of every limited direction and the pipes the host must have: one per direction,
// with its bandwidth.
func (s *Service) shapingPlan() (map[render.PipeKey]int, []reconcile.PipeDesired, error) {
	devs := s.shapedDevices()
	keys := make([]render.PipeKey, len(devs))
	for i, d := range devs {
		keys[i] = d.key
	}
	ctx := context.Background()
	s.pipes.mu.Lock()
	defer s.pipes.mu.Unlock()
	s.loadPipes(ctx)
	numbers, err := render.AllocatePipes(s.pipes.nums, keys)
	if err != nil {
		return nil, nil, err
	}
	if !maps.Equal(numbers, s.pipes.nums) {
		// the numbers are not used before they are saved: a restart that did not find them would number the pipes again
		// and give one jail's limit to another
		prev := s.pipes.nums
		s.pipes.nums = numbers
		if err := s.savePipes(ctx); err != nil {
			s.pipes.nums = prev
			return nil, nil, err
		}
	}
	var want []reconcile.PipeDesired
	for _, d := range devs {
		want = append(want, reconcile.PipeDesired{Number: numbers[d.key], Rate: d.rate})
	}
	return numbers, want, nil
}

// hasShaping says whether any device of any jail has a bandwidth limit: only then does the host need dummynet.
func (s *Service) hasShaping() bool { return len(s.shapedDevices()) > 0 }

// ensurePipes loads dummynet and configures the pipes of one jail before its anchor is loaded: a packet sent into a pipe
// that does not exist is lost, and the reconcile loop that keeps all pipes right runs on its own schedule.
func (s *Service) ensurePipes(ctx context.Context, shapes []render.Shape, rates map[int]uint64) error {
	if len(shapes) == 0 || s.d.Run == nil {
		return nil
	}
	if _, err := s.d.Run.Run(ctx, run.Cmd{Name: "kldstat", Args: []string{"-n", DummynetModule}}); err != nil {
		if _, err := s.d.Run.Run(ctx, run.Cmd{Name: "kldload", Args: []string{DummynetModule}}); err != nil {
			return fmt.Errorf("the kernel module %s is not loaded and cannot be loaded, so the bandwidth limits of the jail cannot be enforced: %w", DummynetModule, err)
		}
	}
	for _, sh := range shapes {
		for _, p := range []int{sh.Egress, sh.Ingress} {
			if p == 0 {
				continue
			}
			if err := s.configurePipe(ctx, p, rates[p]); err != nil {
				return err
			}
		}
	}
	return nil
}

// configurePipe sets the bandwidth of one pipe: dnctl pipe N config bw RATE ("0" is unlimited).
func (s *Service) configurePipe(ctx context.Context, n int, bits uint64) error {
	bw := "0"
	if bits > 0 {
		bw = render.PipeRate(bits)
	}
	_, err := s.d.Run.Run(ctx, run.Cmd{Name: "dnctl", Args: []string{"pipe", strconv.Itoa(n), "config", "bw", bw}})
	if err != nil {
		return fmt.Errorf("dnctl pipe %d config bw %s: %s", n, bw, strings.TrimSpace(err.Error()))
	}
	return nil
}
