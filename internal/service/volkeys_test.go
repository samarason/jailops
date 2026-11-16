package service_test

import (
	"context"
	"strings"
	"sync"
	"testing"
	"time"

	"jailops.net/jailops/internal/daemon"
	"jailops.net/jailops/internal/daemon/dtest"
	"jailops.net/jailops/internal/service"
	"jailops.net/jailops/sdk/api"
)

const (
	encPass  = "marker-5e1f-long-passphrase"
	encNew   = "marker-77aa-other-passphrase"
	encWrong = "marker-dead-wrong-passphrase"
	encVol   = "tank/jailops/projects/" + dtest.SeedProject + "/volumes/vault"
)

// testClock is a clock the test moves.
type testClock struct {
	mu  sync.Mutex
	now time.Time
}

func (c *testClock) Now() time.Time          { c.mu.Lock(); defer c.mu.Unlock(); return c.now }
func (c *testClock) Advance(d time.Duration) { c.mu.Lock(); c.now = c.now.Add(d); c.mu.Unlock() }

func encEnv(t *testing.T) (*dtest.Env, *service.Service, *testClock) {
	t.Helper()
	clk := &testClock{now: time.Now()}
	// no boot pass: the tests call the boot's start themselves (s.StartJail), deterministically
	e := dtest.New(t, dtest.Options{Now: clk.Now, Mutate: noAutostart})
	e.Seed()
	return e, e.D.Service(), clk
}

func noAutostart(c *daemon.Config) { off := false; c.Reconcile.Autostart = &off }

func vaultJail() api.Jail {
	j := dtest.WebJail("vault")
	j.Spec.Volumes = []api.VolumeAttach{{Name: "vault", Mount: "/var/db/app"}}
	j.Spec.Boot.Autostart = true
	return j
}

func mustOp(t *testing.T, s *service.Service, op api.Operation, err error) api.Operation {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
	got := wait(t, s, op)
	if got.Status != api.OpSuccess {
		t.Fatalf("%s: %+v", got.Description, got.Error)
	}
	return got
}

func failedWith(t *testing.T, s *service.Service, op api.Operation, err error, code api.Code) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
	got := wait(t, s, op)
	if got.Status != api.OpFailure || got.Error == nil || got.Error.Code != code {
		t.Fatalf("want a failure %s, got %+v", code, got)
	}
}

func createVault(t *testing.T, s *service.Service, ctx context.Context) {
	t.Helper()
	vop, err := s.CreateVolume(ctx, api.VolumeCreate{Metadata: api.ObjectMeta{Name: "vault"}, Spec: api.VolumeSpec{Encrypted: true, UID: 770, GID: 770, Mode: "0700"}, Passphrase: encPass})
	mustOp(t, s, vop, err)
	j := vaultJail()
	op, err := s.CreateJail(ctx, j)
	mustOp(t, s, op, err)
}

// reboot stops the jail and unloads the keys, as a host boot leaves them, and makes the daemon read the jails again.
func reboot(t *testing.T, e *dtest.Env, s *service.Service, ctx context.Context) {
	t.Helper()
	if j, _ := s.GetJail(ctx, "vault"); j.Status.Power == api.PowerRunning {
		op, err := s.JailAction(ctx, "vault", api.JailAction{Action: "stop"})
		mustOp(t, s, op, err)
	}
	e.Keys.Reboot()
	if err := s.RefreshJails(ctx); err != nil {
		t.Fatal(err)
	}
}

func power(t *testing.T, s *service.Service, ctx context.Context) api.JailStatus {
	t.Helper()
	j, err := s.GetJail(ctx, "vault")
	if err != nil {
		t.Fatal(err)
	}
	return j.Status
}

func TestEncryptedVolumeLifecycle(t *testing.T) {
	e, s, _ := encEnv(t)
	ctx := as(globalAdmin, dtest.SeedProject)
	createVault(t, s, ctx)
	if e.Keys.Passphrase(encVol) != encPass {
		t.Fatalf("the helper got %q", e.Keys.Passphrase(encVol))
	}
	if st := power(t, s, ctx); st.Power != api.PowerStopped || st.Locked != nil {
		t.Fatalf("a new jail is unlocked: %+v", st)
	}
	op, err := s.JailAction(ctx, "vault", api.JailAction{Action: "start"})
	mustOp(t, s, op, err)

	reboot(t, e, s, ctx)
	if st := power(t, s, ctx); st.Power != api.PowerLocked || len(st.Locked) != 1 || st.Locked[0] != "vault" {
		t.Fatalf("after a reboot: %+v", st)
	}
	_, err = s.JailAction(ctx, "vault", api.JailAction{Action: "start"})
	wantCode(t, err, api.CodeLocked)
	if !strings.Contains(hintOf(err), "jailops volume unlock vault") {
		t.Fatalf("hint %q", hintOf(err))
	}
	_, err = s.JailAction(ctx, "vault", api.JailAction{Action: "restart"})
	wantCode(t, err, api.CodeLocked)

	op, err = s.UnlockVolume(ctx, "vault", api.VolumeUnlock{Passphrase: encWrong})
	failedWith(t, s, op, err, api.CodeBadPassphrase)
	if st := power(t, s, ctx); st.Power != api.PowerLocked {
		t.Fatalf("a wrong passphrase unlocked: %+v", st)
	}
	// unlocked without --start and without a boot that wanted it: stopped
	op, err = s.UnlockVolume(ctx, "vault", api.VolumeUnlock{Passphrase: encPass})
	mustOp(t, s, op, err)
	if st := power(t, s, ctx); st.Power != api.PowerStopped || st.Locked != nil {
		t.Fatalf("after the unlock: %+v", st)
	}
	// lock: stopped and locked; unlock with start: running
	op, err = s.JailAction(ctx, "vault", api.JailAction{Action: "start"})
	mustOp(t, s, op, err)
	op, err = s.LockVolume(ctx, "vault")
	mustOp(t, s, op, err)
	if st := power(t, s, ctx); st.Power != api.PowerLocked {
		t.Fatalf("after the lock: %+v", st)
	}
	op, err = s.UnlockVolume(ctx, "vault", api.VolumeUnlock{Passphrase: encPass, Start: true})
	mustOp(t, s, op, err)
	if st := power(t, s, ctx); st.Power != api.PowerRunning {
		t.Fatalf("unlock --start: %+v", st)
	}

	// the passphrase changes; a locked jail cannot change it
	op, err = s.ChangeVolumePassphrase(ctx, "vault", api.VolumePassphraseChange{Old: encWrong, New: encNew})
	failedWith(t, s, op, err, api.CodeBadPassphrase)
	_, err = s.ChangeVolumePassphrase(ctx, "vault", api.VolumePassphraseChange{Old: encPass, New: "short"})
	wantCode(t, err, api.CodeInvalid)
	op, err = s.ChangeVolumePassphrase(ctx, "vault", api.VolumePassphraseChange{Old: encPass, New: encNew})
	mustOp(t, s, op, err)
	if e.Keys.Passphrase(encVol) != encNew {
		t.Fatal("the passphrase did not change")
	}
	reboot(t, e, s, ctx)
	op, err = s.ChangeVolumePassphrase(ctx, "vault", api.VolumePassphraseChange{Old: encNew, New: encPass})
	failedWith(t, s, op, err, api.CodeLocked)
	op, err = s.UnlockVolume(ctx, "vault", api.VolumeUnlock{Passphrase: encNew})
	mustOp(t, s, op, err)

	// the encryption of a volume cannot change later
	v, _ := s.GetVolume(ctx, "vault")
	v.Spec.Encrypted = false
	_, err = s.UpdateVolume(ctx, "vault", v, service.AnyGeneration)
	wantCode(t, err, api.CodeInvalid)

	// a volume that is not encrypted has nothing to unlock
	pop, err := s.CreateVolume(ctx, api.VolumeCreate{Metadata: api.ObjectMeta{Name: "plain"}})
	mustOp(t, s, pop, err)
	_, err = s.UnlockVolume(ctx, "plain", api.VolumeUnlock{Passphrase: encPass})
	wantCode(t, err, api.CodeInvalid)
	_, err = s.LockVolume(ctx, "plain")
	wantCode(t, err, api.CodeInvalid)
	// an encrypted volume is attached to one jail only
	op, err = s.CreateJail(ctx, dtest.WebJail("second"))
	mustOp(t, s, op, err)
	aop, err := s.AttachVolume(ctx, "second", api.VolumeAttachRequest{Volume: "vault", Mount: "/srv/v"})
	failedWith(t, s, aop, err, api.CodeConflict)
}

func TestBootStartsALockedJailAfterItsUnlock(t *testing.T) {
	e, s, _ := encEnv(t)
	ctx := as(globalAdmin, dtest.SeedProject)
	createVault(t, s, ctx)
	reboot(t, e, s, ctx)
	key := dtest.SeedProject + "_vault"
	// what the boot pass of the reconciler calls for a jail with boot.autostart
	err := s.StartJail(ctx, key)
	wantCode(t, err, api.CodeLocked)
	if st := power(t, s, ctx); st.Power != api.PowerLocked {
		t.Fatalf("%+v", st)
	}
	op, err := s.UnlockVolume(ctx, "vault", api.VolumeUnlock{Passphrase: encPass})
	mustOp(t, s, op, err)
	if st := power(t, s, ctx); st.Power != api.PowerRunning {
		t.Fatalf("the jail the boot wanted is not started after its unlock: %+v", st)
	}
	// once started, the wish is gone: a later unlock after a lock leaves it stopped
	op, err = s.LockVolume(ctx, "vault")
	mustOp(t, s, op, err)
	op, err = s.UnlockVolume(ctx, "vault", api.VolumeUnlock{Passphrase: encPass})
	mustOp(t, s, op, err)
	if st := power(t, s, ctx); st.Power != api.PowerStopped {
		t.Fatalf("%+v", st)
	}
}

func TestBootWishIsMemoryOnly(t *testing.T) {
	e, s, _ := encEnv(t)
	ctx := as(globalAdmin, dtest.SeedProject)
	createVault(t, s, ctx)
	reboot(t, e, s, ctx)
	wantCode(t, s.StartJail(ctx, dtest.SeedProject+"_vault"), api.CodeLocked)
	// a daemon restart forgets the wish: the unlock alone does not start the jail
	e.Stop()
	e2 := dtest.New(t, dtest.Options{Reuse: e, Mutate: noAutostart})
	s2 := e2.D.Service()
	op, err := s2.UnlockVolume(ctx, "vault", api.VolumeUnlock{Passphrase: encPass})
	mustOp(t, s2, op, err)
	if st := power(t, s2, ctx); st.Power != api.PowerStopped {
		t.Fatalf("%+v", st)
	}
	// the boot pass of the restarted daemon derives the wish again from boot.autostart
	op, err = s2.LockVolume(ctx, "vault")
	mustOp(t, s2, op, err)
	wantCode(t, s2.StartJail(ctx, dtest.SeedProject+"_vault"), api.CodeLocked)
	op, err = s2.UnlockVolume(ctx, "vault", api.VolumeUnlock{Passphrase: encPass})
	mustOp(t, s2, op, err)
	if st := power(t, s2, ctx); st.Power != api.PowerRunning {
		t.Fatalf("%+v", st)
	}
}

func TestUnlockLockout(t *testing.T) {
	e, s, clk := encEnv(t)
	ctx := as(globalAdmin, dtest.SeedProject)
	createVault(t, s, ctx)
	reboot(t, e, s, ctx)
	for i := 0; i < 5; i++ {
		op, err := s.UnlockVolume(ctx, "vault", api.VolumeUnlock{Passphrase: encWrong})
		failedWith(t, s, op, err, api.CodeBadPassphrase)
	}
	_, err := s.UnlockVolume(ctx, "vault", api.VolumeUnlock{Passphrase: encPass})
	wantCode(t, err, api.CodeRateLimited)
	_, err = s.ChangeVolumePassphrase(ctx, "vault", api.VolumePassphraseChange{Old: encPass, New: encNew})
	wantCode(t, err, api.CodeRateLimited)
	clk.Advance(29 * time.Second)
	_, err = s.UnlockVolume(ctx, "vault", api.VolumeUnlock{Passphrase: encPass})
	wantCode(t, err, api.CodeRateLimited)
	clk.Advance(2 * time.Second)
	op, err := s.UnlockVolume(ctx, "vault", api.VolumeUnlock{Passphrase: encPass})
	mustOp(t, s, op, err)
	// a success forgets the failures: four wrong ones do not lock out
	op, err = s.LockVolume(ctx, "vault")
	mustOp(t, s, op, err)
	for i := 0; i < 4; i++ {
		op, err := s.UnlockVolume(ctx, "vault", api.VolumeUnlock{Passphrase: encWrong})
		failedWith(t, s, op, err, api.CodeBadPassphrase)
	}
	op, err = s.UnlockVolume(ctx, "vault", api.VolumeUnlock{Passphrase: encPass})
	mustOp(t, s, op, err)
}

// Unlocks of one jail run one at a time (or are refused as busy); the failures are counted exactly and nothing races.
func TestConcurrentUnlocks(t *testing.T) {
	e, s, _ := encEnv(t)
	ctx := as(globalAdmin, dtest.SeedProject)
	createVault(t, s, ctx)
	reboot(t, e, s, ctx)
	var wg sync.WaitGroup
	var mu sync.Mutex
	bad := 0
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			op, err := s.UnlockVolume(ctx, "vault", api.VolumeUnlock{Passphrase: encWrong})
			if err == nil {
				if op = wait(t, s, op); op.Error != nil {
					err = &api.Error{Code: op.Error.Code}
				}
			}
			mu.Lock()
			defer mu.Unlock()
			switch {
			case api.IsCode(err, api.CodeBadPassphrase):
				bad++
			case api.IsCode(err, api.CodeRateLimited), api.IsCode(err, api.CodeBusy):
			default:
				t.Errorf("unexpected %v", err)
			}
		}()
	}
	wg.Wait()
	if bad < 1 || bad > 5 {
		t.Fatalf("%d wrong passphrases counted", bad)
	}
	// exactly 5 wrong passphrases in all before the lockout
	for ; bad < 5; bad++ {
		op, err := s.UnlockVolume(ctx, "vault", api.VolumeUnlock{Passphrase: encWrong})
		failedWith(t, s, op, err, api.CodeBadPassphrase)
	}
	_, err := s.UnlockVolume(ctx, "vault", api.VolumeUnlock{Passphrase: encPass})
	wantCode(t, err, api.CodeRateLimited)
	if st := power(t, s, ctx); st.Power != api.PowerLocked {
		t.Fatalf("%+v", st)
	}
}

func TestCreateEncryptedValidation(t *testing.T) {
	_, s, _ := encEnv(t)
	ctx := as(globalAdmin, dtest.SeedProject)
	enc := api.VolumeSpec{Encrypted: true}
	for name, c := range map[string]struct {
		in   api.VolumeCreate
		code api.Code
	}{
		"no passphrase":       {api.VolumeCreate{Metadata: api.ObjectMeta{Name: "v"}, Spec: enc}, api.CodeInvalid},
		"short":               {api.VolumeCreate{Metadata: api.ObjectMeta{Name: "v"}, Spec: enc, Passphrase: "too-short"}, api.CodeInvalid},
		"a line break":        {api.VolumeCreate{Metadata: api.ObjectMeta{Name: "v"}, Spec: enc, Passphrase: "marker-long-enough\nx"}, api.CodeInvalid},
		"nothing to encrypt":  {api.VolumeCreate{Metadata: api.ObjectMeta{Name: "v"}, Passphrase: encPass}, api.CodeInvalid},
		"over 512 bytes long": {api.VolumeCreate{Metadata: api.ObjectMeta{Name: "v"}, Spec: enc, Passphrase: strings.Repeat("p", 513)}, api.CodeInvalid},
	} {
		_, err := s.CreateVolume(ctx, c.in)
		if !api.IsCode(err, c.code) {
			t.Errorf("%s: want %s, got %v", name, c.code, err)
		}
	}
	// a host without the helper's key operations
	e2 := dtest.New(t, dtest.Options{Clients: func(c *daemon.Clients) { c.Keys = nil }})
	e2.Seed()
	_, err := e2.D.Service().CreateVolume(ctx, api.VolumeCreate{Metadata: api.ObjectMeta{Name: "v"}, Spec: enc, Passphrase: encPass})
	wantCode(t, err, api.CodeUnsupported)
}

func doctorCheck(r api.DoctorReport, name string) (api.DoctorCheck, bool) {
	for _, c := range r.Checks {
		if c.Name == name {
			return c, true
		}
	}
	return api.DoctorCheck{}, false
}

func TestDoctorReportsLockedJailsAndThePoolFeature(t *testing.T) {
	e, s, _ := encEnv(t)
	ctx := as(globalAdmin, dtest.SeedProject)
	if c, ok := doctorCheck(s.Doctor(ctx), "volumes.encryption"); !ok || c.Status != api.DoctorOK {
		t.Fatalf("%+v", c)
	}
	if _, ok := doctorCheck(s.Doctor(ctx), "volumes.locked"); ok {
		t.Fatal("volumes.locked without any encrypted volume")
	}
	createVault(t, s, ctx)
	if c, _ := doctorCheck(s.Doctor(ctx), "volumes.locked"); c.Status != api.DoctorOK {
		t.Fatalf("%+v", c)
	}
	reboot(t, e, s, ctx)
	c, _ := doctorCheck(s.Doctor(ctx), "volumes.locked")
	if c.Status != api.DoctorInfo || c.Message != "1 jail(s) wait for a passphrase: vault" {
		t.Fatalf("%+v", c)
	}
	e.ZFS.SetFeatureState("tank", "encryption", "disabled")
	if c, _ := doctorCheck(s.Doctor(ctx), "volumes.encryption"); c.Status != api.DoctorFail {
		t.Fatalf("a pool holding encrypted volumes without the feature: %+v", c)
	}
	// a host without encrypted volumes is only warned
	e2, s2, _ := encEnv(t)
	e2.ZFS.SetFeatureState("tank", "encryption", "disabled")
	if c, _ := doctorCheck(s2.Doctor(ctx), "volumes.encryption"); c.Status != api.DoctorWarn || !strings.Contains(c.Hint, "zpool set feature@encryption=enabled tank") {
		t.Fatalf("%+v", c)
	}
}
