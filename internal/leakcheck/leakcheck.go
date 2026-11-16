// Package leakcheck measures what a piece of code leaves behind: goroutines, open file descriptors and heap.
// Nothing here is used by production code; the tests of the long-running programs use it.
package leakcheck

import (
	"fmt"
	"os"
	"runtime"
	"sort"
	"strings"
	"testing"
	"time"
)

// Enabled reports whether the checks that fail today are run (JAILOPS_LEAKCHECK=1). Checks that pass run always.
func Enabled() bool { return os.Getenv("JAILOPS_LEAKCHECK") == "1" }

// Baseline is a measurement taken before the code under test runs.
type Baseline struct {
	goroutines int
	groups     map[string]int
	fds        int
	heap       uint64
}

// Take settles the process (finished goroutines exit, garbage is collected) and measures it.
func Take() Baseline {
	n := settle()
	return Baseline{goroutines: n, groups: groups(), fds: FDs(), heap: heapInUse()}
}

// settle waits until the number of goroutines stops changing.
func settle() int {
	prev, same := -1, 0
	for i := 0; i < 200; i++ {
		runtime.GC()
		runtime.Gosched()
		time.Sleep(15 * time.Millisecond)
		n := runtime.NumGoroutine()
		if n == prev {
			if same++; same >= 5 {
				return n
			}
		} else {
			prev, same = n, 0
		}
	}
	return runtime.NumGoroutine()
}

func heapInUse() uint64 {
	var m runtime.MemStats
	runtime.GC()
	runtime.ReadMemStats(&m)
	return m.HeapAlloc
}

// FDs is the number of open file descriptors of the process (-1 where /proc/self/fd does not exist).
func FDs() int {
	ents, err := os.ReadDir("/proc/self/fd")
	if err != nil {
		return -1
	}
	return len(ents)
}

// groups counts the goroutines by the function that created them (or the function they run, for the main ones).
func groups() map[string]int {
	buf := make([]byte, 1<<20)
	for {
		n := runtime.Stack(buf, true)
		if n < len(buf) {
			buf = buf[:n]
			break
		}
		buf = make([]byte, 2*len(buf))
	}
	out := map[string]int{}
	for _, g := range strings.Split(string(buf), "\n\n") {
		lines := strings.Split(strings.TrimSpace(g), "\n")
		if len(lines) < 2 {
			continue
		}
		key := lines[1]
		for _, l := range lines {
			if strings.HasPrefix(l, "created by ") {
				key = strings.TrimSpace(l)
			}
		}
		if i := strings.Index(key, " in goroutine"); i > 0 {
			key = key[:i]
		}
		out[key]++
	}
	return out
}

// Verify fails t if goroutines or descriptors grew by more than slack since the baseline, naming where the new
// goroutines were created, and returns the heap growth in bytes for the caller to judge.
func (b Baseline) Verify(t testing.TB, what string, slackGoroutines, slackFDs int) (heapGrowth int64) {
	t.Helper()
	n := settle()
	g := groups()
	if n > b.goroutines+slackGoroutines {
		type row struct {
			where string
			n     int
		}
		var rows []row
		for k, v := range g {
			if d := v - b.groups[k]; d > 0 {
				rows = append(rows, row{k, d})
			}
		}
		sort.Slice(rows, func(i, j int) bool { return rows[i].n > rows[j].n })
		var sb strings.Builder
		for i, r := range rows {
			if i == 8 {
				break
			}
			fmt.Fprintf(&sb, "\n  +%d  %s", r.n, r.where)
		}
		t.Errorf("%s: goroutines %d -> %d (slack %d); created by:%s", what, b.goroutines, n, slackGoroutines, sb.String())
	}
	if fds := FDs(); b.fds >= 0 && fds > b.fds+slackFDs {
		t.Errorf("%s: open descriptors %d -> %d (slack %d)", what, b.fds, fds, slackFDs)
	}
	return int64(heapInUse()) - int64(b.heap)
}
