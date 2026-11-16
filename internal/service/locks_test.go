package service

import (
	"context"
	"testing"
	"time"

	"jailops.net/jailops/sdk/api"
)

// Several jails of one network are started at once: the second preparation of the network waits for the first one
// instead of answering busy; any other holder of the network still makes it busy.
func TestLockPatientWaitsForANetworkPreparation(t *testing.T) {
	l := newLockSet()
	release, err := l.tryLock("prepare network lan", networkLock("lan"))
	if err != nil {
		t.Fatal(err)
	}
	go func() {
		time.Sleep(200 * time.Millisecond)
		release()
	}()
	start := time.Now()
	unlock, err := l.lockPatient(context.Background(), "prepare network lan", networkLock("lan"))
	if err != nil {
		t.Fatalf("the second preparation did not wait: %v", err)
	}
	unlock()
	if time.Since(start) < 150*time.Millisecond {
		t.Fatal("it did not wait for the first one")
	}

	other, err := l.tryLock("delete network lan", networkLock("lan"))
	if err != nil {
		t.Fatal(err)
	}
	defer other()
	if _, err := l.lockPatient(context.Background(), "prepare network lan", networkLock("lan")); !api.IsCode(err, api.CodeBusy) {
		t.Fatalf("a network that is being deleted is not to be waited for: %v", err)
	}
}
