package service

import (
	"testing"
	"time"
)

func TestParseAutoUpgradeAt(t *testing.T) {
	for in, want := range map[string]int{"": 180, "03:00": 180, "00:00": 0, "23:59": 23*60 + 59, "04:30": 270} {
		if got, err := parseAutoUpgradeAt(in); err != nil || got != want {
			t.Errorf("%q: %d %v", in, got, err)
		}
	}
	for _, in := range []string{"3:00", "24:00", "12:60", "noon", "03-00", "03:0", "-1:00", "03:00:00"} {
		if _, err := parseAutoUpgradeAt(in); err == nil {
			t.Errorf("%q was accepted", in)
		}
	}
}

func TestAutoUpgradeDueAndNext(t *testing.T) {
	loc := time.UTC
	at := 3 * 60
	day := func(d, h, m int) time.Time { return time.Date(2026, 11, d, h, m, 0, 0, loc) }
	for _, c := range []struct {
		name      string
		now, last time.Time
		due       bool
		next      time.Time
	}{
		{"before the time, never ran", day(5, 2, 59), time.Time{}, false, day(5, 3, 0)},
		{"at the time, never ran", day(5, 3, 0), time.Time{}, true, day(6, 3, 0)},
		{"an hour after, ran last night", day(5, 4, 0), day(4, 3, 0), true, day(6, 3, 0)},
		{"an hour after, ran tonight", day(5, 4, 0), day(5, 3, 0), false, day(6, 3, 0)},
		{"just inside the catch-up window", day(5, 6, 59), day(4, 3, 0), true, day(6, 3, 0)},
		{"after the catch-up window: waits for tomorrow", day(5, 7, 0), day(4, 3, 0), false, day(6, 3, 0)},
		{"late evening, ran this morning", day(5, 22, 0), day(5, 3, 1), false, day(6, 3, 0)},
		{"a run that started after the slot counts", day(5, 3, 30), day(5, 3, 5), false, day(6, 3, 0)},
	} {
		if got := autoUpgradeDue(c.now, c.last, at); got != c.due {
			t.Errorf("%s: due %v, want %v", c.name, got, c.due)
		}
		if got := nextAutoUpgrade(c.now, at); !got.Equal(c.next) {
			t.Errorf("%s: next %v, want %v", c.name, got, c.next)
		}
	}
}

// The time of day follows the zone of the host, across a change of daylight saving time.
func TestAutoUpgradeFollowsTheZone(t *testing.T) {
	ny, err := time.LoadLocation("America/New_York")
	if err != nil {
		t.Skip("no zone database")
	}
	now := time.Date(2026, 11, 1, 1, 30, 0, 0, ny) // the night the clocks go back
	next := nextAutoUpgrade(now, 3*60)
	if next.Hour() != 3 || next.Day() != 1 {
		t.Fatalf("%v", next)
	}
	if n2 := nextAutoUpgrade(time.Date(2026, 11, 1, 3, 30, 0, 0, ny), 3*60); n2.Hour() != 3 || n2.Day() != 2 {
		t.Fatalf("%v", n2)
	}
}
