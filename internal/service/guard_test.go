package service_test

import (
	"sync"
	"testing"

	"jailops.net/jailops/internal/auth"
	"jailops.net/jailops/sdk/api"
)

// Wrong guesses of the current password are counted before they are checked: a burst of them sent at once is not
// verified one by one past the threshold.
func TestPasswordGuessesAreCountedBeforeTheyAreChecked(t *testing.T) {
	_, s := newEnv(t)
	g := as(globalAdmin, "")
	if _, err := s.CreateUser(g, api.UserCreate{Metadata: api.ObjectMeta{Name: "ann"}, Password: "a long and unusual pass phrase 1",
		Spec: api.UserSpec{Permission: api.PermAdmin, Global: true}}); err != nil {
		t.Fatal(err)
	}
	_, before := auth.DerivationStats()
	var wg sync.WaitGroup
	for i := 0; i < 150; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_ = s.ChangePassword(g, "ann", "wrong guess", "another unusual pass phrase 2")
		}()
	}
	wg.Wait()
	_, after := auth.DerivationStats()
	if n := after - before; n > 12 {
		t.Fatalf("%d passwords were derived for 150 wrong guesses at once: the burst was not held back by the lockout", n)
	}
}
