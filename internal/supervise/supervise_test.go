package supervise

import (
	"context"
	"io"
	"log/slog"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func quiet() *slog.Logger { return slog.New(slog.NewTextHandler(io.Discard, nil)) }

func TestAPanicRestartsTheLoopAndANormalReturnEndsIt(t *testing.T) {
	Reset()
	var waits []time.Duration
	sleep = func(_ context.Context, d time.Duration) bool { waits = append(waits, d); return true }
	defer func() { sleep = realSleep }()
	var runs atomic.Int32
	Run(context.Background(), quiet(), "reconcile", func(context.Context) {
		if runs.Add(1) <= 3 {
			panic("odd state")
		}
	})
	if runs.Load() != 4 {
		t.Fatalf("the loop ran %d times, want 4 (three panics, then it returned)", runs.Load())
	}
	if len(waits) != 3 || waits[0] < MinDelay || waits[0] > MinDelay*6/5 || waits[1] < 2*MinDelay || waits[2] < 4*MinDelay {
		t.Fatalf("the delays double from a second: %v", waits)
	}
	l := Loops()
	if len(l) != 1 || l[0].Name != "reconcile" || l[0].Restarts != 3 || l[0].Recent != 3 || l[0].LastPanic != "odd state" {
		t.Fatalf("loops: %+v", l)
	}
}

func TestTheDelayIsBoundedAndStartsAgainAfterAHealthyRun(t *testing.T) {
	Reset()
	clock := time.Unix(1_000_000, 0)
	now = func() time.Time { return clock }
	var waits []time.Duration
	sleep = func(_ context.Context, d time.Duration) bool {
		waits = append(waits, d)
		clock = clock.Add(d)
		return true
	}
	defer func() { now, sleep = time.Now, realSleep }()
	var runs int
	Run(context.Background(), quiet(), "x", func(context.Context) {
		runs++
		if runs == 9 {
			clock = clock.Add(Healthy) // a long healthy run, then a panic
		}
		if runs <= 10 {
			panic("again")
		}
	})
	for i, w := range waits {
		if w > MaxDelay*6/5 {
			t.Fatalf("delay %d is %v, above the bound", i, w)
		}
	}
	if waits[7] < MaxDelay { // the eighth restart is at the bound
		t.Fatalf("delays %v", waits)
	}
	if after := waits[8]; after > MinDelay*6/5 { // the wait after the panic that followed the healthy run
		t.Fatalf("after a healthy run the delay starts again at a second, got %v", after)
	}
}

func TestACancelledContextEndsTheWait(t *testing.T) {
	Reset()
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		Run(ctx, quiet(), "y", func(context.Context) { panic("boom") })
		close(done)
	}()
	time.Sleep(50 * time.Millisecond)
	cancel()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("Run did not return after the context ended")
	}
}

func TestThePanicTextKeepsTheStackOutOfTheStats(t *testing.T) {
	Reset()
	sleep = func(context.Context, time.Duration) bool { return false }
	defer func() { sleep = realSleep }()
	Run(context.Background(), quiet(), "z", func(context.Context) { panic(strings.Repeat("a", 10)) })
	if l := Loops(); len(l) != 1 || strings.Contains(l[0].LastPanic, "\n") {
		t.Fatalf("%+v", l)
	}
}

func TestGuardTurnsAPanicIntoAnError(t *testing.T) {
	Reset()
	err := Guard(quiet(), "worker", func() { var m map[string]int; m["x"] = 1 })
	if err == nil || !strings.Contains(err.Error(), "worker: panic: ") {
		t.Fatalf("err %v", err)
	}
	if err := Guard(quiet(), "worker", func() {}); err != nil {
		t.Fatal(err)
	}
	if l := Loops(); len(l) != 1 || l[0].Restarts != 1 {
		t.Fatalf("%+v", l)
	}
}
