package ndproxy

import (
	"testing"
	"time"
)

type countingClock struct {
	now   time.Time
	after int
}

func (c *countingClock) Now() time.Time { return c.now }
func (c *countingClock) After(time.Duration) <-chan time.Time {
	c.after++
	return make(chan time.Time, 1)
}

func TestLoopTimerIsKeptUntilItFiresOrTheDeadlineMoves(t *testing.T) {
	c := &countingClock{now: time.Unix(1000, 0)}
	var lt loopTimer
	at := c.now.Add(time.Second)
	first := lt.until(c, at)
	for i := 0; i < 1000; i++ { // a flood of frames wakes the loop a thousand times with the same deadlines
		if lt.until(c, at) != first {
			t.Fatal("the same deadline got another timer")
		}
	}
	if c.after != 1 {
		t.Fatalf("%d timers for one deadline", c.after)
	}
	lt.until(c, at.Add(time.Second)) // the deadline moved
	if c.after != 2 {
		t.Fatalf("a moved deadline needs a new timer: %d", c.after)
	}
	lt.reset() // it fired
	lt.until(c, at.Add(time.Second))
	if c.after != 3 {
		t.Fatalf("after a reset: %d", c.after)
	}
	var poll loopTimer
	for i := 0; i < 100; i++ {
		poll.after(c, time.Second)
	}
	if c.after != 4 {
		t.Fatalf("the poll timer is made once: %d", c.after)
	}
}
