package reconcile

import (
	"testing"
	"time"
)

func TestDebounceGrowsWithThePassButIsBounded(t *testing.T) {
	base := 200 * time.Millisecond
	for _, c := range []struct{ took, want time.Duration }{
		{0, base},                      // a pass on a small host: the configured wait
		{20 * time.Millisecond, base},  // quick passes: unchanged
		{time.Second, 3 * time.Second}, // a host with thousands of jails: a quarter of the time at most
		{time.Minute, maxDebounce},     // never longer than the bound
	} {
		if got := debounceWait(base, c.took); got != c.want {
			t.Errorf("pass of %v: waited %v, want %v", c.took, got, c.want)
		}
	}
}
