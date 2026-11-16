package pfctl

import (
	"context"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestMutates(t *testing.T) {
	for args, want := range map[string]bool{
		"-n -v -a x -f -":     false,
		"-a x -f -":           true,
		"-a x -F rules":       true,
		"-a x -sr":            false,
		"-a x -t t -T add 1":  true,
		"-a x -t t -T show":   false,
		"-k label":            true,
		"-a x -t t -T delete": true,
	} {
		if got := mutates(splitFields(args)); got != want {
			t.Errorf("%q: %v", args, got)
		}
	}
}

func splitFields(s string) []string {
	var out []string
	cur := ""
	for _, r := range s + " " {
		if r == ' ' {
			if cur != "" {
				out = append(out, cur)
			}
			cur = ""
			continue
		}
		cur += string(r)
	}
	return out
}

// Two changes of the packet filter never run at once, in one process or in two.
func TestChangesAreOneAtATime(t *testing.T) {
	old := LockPath
	LockPath = filepath.Join(t.TempDir(), "pf.lock")
	defer func() { LockPath = old }()
	var inside, worst int32
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			unlock, err := lockPF(context.Background())
			if err != nil {
				t.Error(err)
				return
			}
			n := atomic.AddInt32(&inside, 1)
			for {
				w := atomic.LoadInt32(&worst)
				if n <= w || atomic.CompareAndSwapInt32(&worst, w, n) {
					break
				}
			}
			time.Sleep(5 * time.Millisecond)
			atomic.AddInt32(&inside, -1)
			unlock()
		}()
	}
	wg.Wait()
	if worst != 1 {
		t.Fatalf("%d changes ran at once", worst)
	}
}

// A caller that gives up does not wait for ever.
func TestLockWaitEndsWithTheContext(t *testing.T) {
	old := LockPath
	LockPath = filepath.Join(t.TempDir(), "pf.lock")
	defer func() { LockPath = old }()
	unlock, err := lockPF(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	defer unlock()
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	if _, err := lockPF(ctx); err == nil {
		t.Fatal("the second lock was given")
	}
}
