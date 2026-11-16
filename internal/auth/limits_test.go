package auth

import (
	"context"
	"errors"
	"testing"
	"time"
)

// Attempts in flight count: the threshold cannot be passed by attempts sent at once, and after a lock has run out
// one attempt at a time is let through.
func TestLockoutCountsAttemptsInFlight(t *testing.T) {
	now := time.Date(2026, 5, 1, 12, 0, 0, 0, time.UTC)
	l := NewLockout(LockoutConfig{Threshold: 3, BaseDelay: 30 * time.Second, Now: func() time.Time { return now }})
	var locked *LockedError
	for i := range 3 {
		if err := l.Begin("k"); err != nil {
			t.Fatalf("attempt %d: %v", i+1, err)
		}
	}
	if err := l.Begin("k"); !errors.As(err, &locked) {
		t.Fatalf("a fourth attempt in flight: %v", err)
	}
	l.Abort("k")
	if err := l.Begin("k"); err != nil {
		t.Fatalf("after an abort: %v", err)
	}
	for range 2 {
		_ = l.End("k", false)
	}
	if err := l.End("k", false); !errors.As(err, &locked) || locked.RetryAfter != 30*time.Second {
		t.Fatalf("the third failure: %v", err)
	}
	if err := l.Begin("k"); !errors.As(err, &locked) {
		t.Fatalf("while locked: %v", err)
	}
	now = now.Add(31 * time.Second)
	if err := l.Begin("k"); err != nil {
		t.Fatalf("after the lock: %v", err)
	}
	if err := l.Begin("k"); !errors.As(err, &locked) {
		t.Fatalf("a second attempt after the lock: %v", err)
	}
	if err := l.End("k", true); err != nil {
		t.Fatal(err)
	}
	if err := l.Begin("k"); err != nil {
		t.Fatalf("after a success: %v", err)
	}
}

func TestSourceKey(t *testing.T) {
	for in, want := range map[string]string{
		"192.0.2.7":                "192.0.2.7",
		"2001:db8:1:2::7":          "2001:db8:1:2::/64",
		"2001:db8:1:2:ffff::1":     "2001:db8:1:2::/64",
		"fe80::1%em0":              "fe80::/64",
		"::ffff:192.0.2.7":         "::ffff:192.0.2.7",
		"unix:1001":                "unix:1001",
		"":                         "",
		"2001:db8:1:3:aaaa:bbbb::": "2001:db8:1:3::/64",
	} {
		if got := SourceKey(in); got != want {
			t.Errorf("SourceKey(%q) = %q, want %q", in, got, want)
		}
	}
}

// Guesses for one account from anywhere: free up to Free failures, then each attempt waits 1s, 2s, 4s ... at most
// MaxDelay; a success forgets them, and so does a quiet half hour.
func TestAccountDelay(t *testing.T) {
	now := time.Date(2026, 5, 1, 12, 0, 0, 0, time.UTC)
	var slept []time.Duration
	a := NewAccountDelay(AccountDelayConfig{Free: 3, MaxDelay: 5 * time.Second, Now: func() time.Time { return now },
		Sleep: func(ctx context.Context, d time.Duration) error { slept = append(slept, d); return nil }})
	try := func(account string, ok bool) {
		t.Helper()
		end, err := a.Begin(context.Background(), account)
		if err != nil {
			t.Fatal(err)
		}
		end(ok)
	}
	for range 7 {
		try("alice", false)
	}
	want := []time.Duration{time.Second, 2 * time.Second, 4 * time.Second, 5 * time.Second}
	if len(slept) != len(want) || slept[0] != want[0] || slept[1] != want[1] || slept[2] != want[2] || slept[3] != want[3] {
		t.Fatalf("waits %v, want %v", slept, want)
	}
	try("bob", false)  // another account is not slowed
	try("alice", true) // waits like any other attempt
	n := len(slept)
	try("alice", false)
	if len(slept) != n {
		t.Fatalf("an attempt after a success waited %v", slept[n:])
	}
	for range 5 {
		try("carol", false)
	}
	now = now.Add(31 * time.Minute)
	n = len(slept)
	try("carol", false)
	if len(slept) != n {
		t.Fatalf("an attempt after a quiet half hour waited %v", slept[n:])
	}
}

// While a slowed attempt for an account waits, another one for the same account is refused at once.
func TestAccountDelayOneSlowAttemptAtATime(t *testing.T) {
	entered := make(chan struct{})
	release := make(chan struct{})
	a := NewAccountDelay(AccountDelayConfig{Free: 1, Sleep: func(ctx context.Context, d time.Duration) error {
		close(entered)
		<-release
		return nil
	}})
	end, err := a.Begin(context.Background(), "alice")
	if err != nil {
		t.Fatal(err)
	}
	end(false)
	done := make(chan struct{})
	go func() {
		defer close(done)
		if end, err := a.Begin(context.Background(), "alice"); err == nil {
			end(false)
		}
	}()
	<-entered
	var locked *LockedError
	if _, err := a.Begin(context.Background(), "alice"); !errors.As(err, &locked) || locked.RetryAfter < time.Second {
		t.Fatalf("a second slowed attempt: %v", err)
	}
	close(release)
	<-done
}
