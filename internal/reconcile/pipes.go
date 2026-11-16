package reconcile

import (
	"context"
	"regexp"
	"slices"
	"strconv"
	"strings"

	"jailops.net/jailops/internal/render"
	"jailops.net/jailops/internal/sys/run"
)

// rePipeLine is a line of `dnctl pipe list`: the pipe number first, zero-padded, then a colon.
var rePipeLine = regexp.MustCompile(`^0*([0-9]+):`)

// pipePass configures the dummynet pipes of the bandwidth limits. It runs after the host pass has loaded dummynet and
// before the anchors that send traffic into the pipes are loaded: a packet that is sent into a pipe that does not
// exist is dropped. It sets a pipe again when a limit changes or when the pipe is gone (a reboot).
func (r *Reconciler) pipePass(ctx context.Context, des Desired, rep *Report) {
	if r.env.Run == nil {
		return
	}
	existing, err := r.listPipes(ctx)
	if err != nil {
		if len(des.Pipes) > 0 {
			rep.Failures["dummynet"] = "the dummynet pipes of the bandwidth limits cannot be read, so the limits are not enforced: " + err.Error()
		}
		return
	}
	have := map[int]bool{}
	for _, n := range existing {
		have[n] = true
	}
	if r.pipeRates == nil {
		r.pipeRates = map[int]uint64{}
	}
	want := map[int]uint64{}
	for _, p := range des.Pipes {
		want[p.Number] = p.Rate
	}
	numbers := make([]int, 0, len(want))
	for n := range want {
		numbers = append(numbers, n)
	}
	slices.Sort(numbers)
	for _, n := range numbers {
		last, known := r.pipeRates[n]
		if have[n] && known && last == want[n] {
			continue
		}
		bw := "0"
		if want[n] > 0 {
			bw = render.PipeRate(want[n])
		}
		if _, err := r.env.Run.Run(ctx, run.Cmd{Name: "dnctl", Args: []string{"pipe", strconv.Itoa(n), "config", "bw", bw}}); err != nil {
			rep.Failures["dummynet"] = "dnctl pipe " + strconv.Itoa(n) + " config bw " + bw + ": " + strings.TrimSpace(err.Error())
			continue
		}
		r.pipeRates[n] = want[n]
		rep.Applied = append(rep.Applied, "dnctl pipe "+strconv.Itoa(n)+" config bw "+bw)
	}
}

// pipeCleanup deletes the pipes of JailOps's range that no jail wants. It runs after the anchors are loaded: an anchor
// that still names a pipe that is gone drops the traffic it sends into it, so a pipe goes away only once no anchor
// names it any more.
func (r *Reconciler) pipeCleanup(ctx context.Context, des Desired, rep *Report) {
	if r.env.Run == nil {
		return
	}
	existing, err := r.listPipes(ctx)
	if err != nil {
		return
	}
	want := map[int]bool{}
	for _, p := range des.Pipes {
		want[p.Number] = true
	}
	var gone []int
	for _, n := range existing {
		if !want[n] && render.IsManagedPipe(n) {
			gone = append(gone, n)
		}
	}
	if len(gone) == 0 {
		return
	}
	// A pipe that a loaded anchor still names stays: a reload that failed keeps the old anchor, and the traffic it
	// sends into a pipe that is gone is dropped.
	named := r.pipesNamedByAnchors(ctx, des)
	for _, n := range gone {
		if named[n] {
			continue
		}
		if _, err := r.env.Run.Run(ctx, run.Cmd{Name: "dnctl", Args: []string{"pipe", "delete", strconv.Itoa(n)}}); err != nil {
			rep.Failures["dummynet"] = "dnctl pipe delete " + strconv.Itoa(n) + ": " + strings.TrimSpace(err.Error())
			continue
		}
		delete(r.pipeRates, n)
		rep.Applied = append(rep.Applied, "dnctl pipe delete "+strconv.Itoa(n))
	}
}

// listPipes returns the numbers of the pipes that exist.
func (r *Reconciler) listPipes(ctx context.Context) ([]int, error) {
	res, err := r.env.Run.Run(ctx, run.Cmd{Name: "dnctl", Args: []string{"pipe", "list"}})
	if err != nil {
		return nil, err
	}
	var out []int
	for _, l := range strings.Split(string(res.Stdout), "\n") {
		if m := rePipeLine.FindStringSubmatch(strings.TrimSpace(l)); m != nil {
			if n, err := strconv.Atoi(m[1]); err == nil {
				out = append(out, n)
			}
		}
	}
	return out, nil
}

// rePipeUse finds the numbers of a dnpipe option in an anchor.
var rePipeUse = regexp.MustCompile(`dnpipe\s*\(?\s*([0-9]+)(?:\s*,\s*([0-9]+))?`)

// pipesNamedByAnchors are the pipe numbers the loaded anchors of the jails send traffic into.
func (r *Reconciler) pipesNamedByAnchors(ctx context.Context, des Desired) map[int]bool {
	named := map[int]bool{}
	if r.env.PF == nil {
		return named
	}
	for _, j := range des.Jails {
		if j.AnchorName == "" {
			continue
		}
		live, err := r.env.PF.Read(ctx, j.AnchorName)
		if err != nil {
			continue
		}
		for _, m := range rePipeUse.FindAllStringSubmatch(live, -1) {
			for _, g := range m[1:] {
				if n, err := strconv.Atoi(g); err == nil && g != "" {
					named[n] = true
				}
			}
		}
	}
	return named
}
