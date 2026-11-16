package hostdir

import (
	"context"
	"testing"
	"time"
)

func TestWithinGivesAHangingProbeUpAsALostDirectory(t *testing.T) {
	release := make(chan struct{})
	defer close(release)
	start := time.Now()
	p, err := Within(context.Background(), 50*time.Millisecond, func(context.Context) (Probe, error) {
		<-release
		return Probe{Mounted: true}, nil
	})
	if err != nil || p.Mounted || p.Detail != "the directory does not answer" || time.Since(start) > 2*time.Second {
		t.Fatalf("%+v %v after %v", p, err, time.Since(start))
	}
	if p.Lost(false) != "the directory does not answer" {
		t.Fatalf("%q", p.Lost(false))
	}
}

func TestWithinPassesAnAnswerOn(t *testing.T) {
	p, err := Within(context.Background(), time.Second, func(context.Context) (Probe, error) { return Probe{Mounted: true, Writable: true}, nil })
	if err != nil || !p.Usable(true) {
		t.Fatalf("%+v %v", p, err)
	}
}
