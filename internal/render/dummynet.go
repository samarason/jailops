package render

import (
	"fmt"
	"sort"
	"strconv"
)

// The bandwidth limit of a jail's device is two dummynet pipes, one for each direction: what the jail sends (egress)
// and what the jail receives (ingress). pf sends the device's packets into the pipe with dnpipe on match rules of the
// jail's anchor, on the host end of the device's epair. That interface is the jail's own link, so one rule sees every
// packet of one jail in one direction: what the jail sends arrives on it (match in), and what is sent to the jail,
// whoever sent it, leaves the host on it (match out).
//
// The pipe numbers are JailOps's own: PipeBase to PipeBase+PipeSpan-1. Nothing else on the host may use them, and the
// reconciler deletes a pipe in that range that no jail wants.
const (
	PipeBase = 40000
	PipeSpan = 20000 // 20000 devices with a limit
)

// PipeKey names a direction of a device with a limit: the jail's stable identity, the index of the device in its
// network list and the direction.
type PipeKey struct {
	Jail    string
	Device  int
	Ingress bool
}

// AllocatePipes gives every key a pipe number and keeps the numbers it had: kept holds the numbers given before (of
// any keys; those of keys that are not asked for are free again), a key that has a number in kept keeps it, and a key
// without one gets the lowest number of JailOps's range that no other key has, in the order of the keys. So a number
// never changes while its key exists, whatever other devices are added or removed: the anchors and the states of the
// other jails keep naming the pipe they were made with. A number outside the range, or given to two keys, is not
// kept.
func AllocatePipes(kept map[PipeKey]int, keys []PipeKey) (map[PipeKey]int, error) {
	if len(keys) > PipeSpan {
		return nil, fmt.Errorf("render: %d directions have a bandwidth limit, at most %d are possible", len(keys), PipeSpan)
	}
	sorted := append([]PipeKey(nil), keys...)
	sort.Slice(sorted, func(i, j int) bool {
		if sorted[i].Jail != sorted[j].Jail {
			return sorted[i].Jail < sorted[j].Jail
		}
		if sorted[i].Device != sorted[j].Device {
			return sorted[i].Device < sorted[j].Device
		}
		return !sorted[i].Ingress && sorted[j].Ingress
	})
	used := map[int]bool{}
	out := make(map[PipeKey]int, len(sorted))
	for _, k := range sorted {
		if _, dup := out[k]; dup {
			continue
		}
		if n, ok := kept[k]; ok && IsManagedPipe(n) && !used[n] {
			used[n] = true
			out[k] = n
		}
	}
	next := PipeBase
	for _, k := range sorted {
		if _, ok := out[k]; ok {
			continue
		}
		for used[next] {
			next++
		}
		used[next] = true
		out[k] = next
	}
	return out, nil
}

// IsManagedPipe says whether a pipe number is in JailOps's range.
func IsManagedPipe(n int) bool { return n >= PipeBase && n < PipeBase+PipeSpan }

// Shape is the bandwidth limit of one device of a jail, as its anchor needs it: the jail's host end of the device's
// epair and the pipes of the two directions (0: no limit in that direction).
type Shape struct {
	Iface           string
	Egress, Ingress int
}

// PipeRate is a bandwidth limit as dnctl takes it: "10000000bit/s".
func PipeRate(bits uint64) string { return strconv.FormatUint(bits, 10) + "bit/s" }
