package validate

import (
	"testing"

	"jailops.net/jailops/sdk/api"
)

func TestStopTimeoutRange(t *testing.T) {
	for _, n := range []int{0, 1, 60, api.MaxStopTimeout} {
		s := api.JailSpec{Image: "fb@stable", Boot: api.BootPolicy{StopTimeout: n}}
		if err := JailSpec("web", s); err != nil {
			t.Errorf("stop timeout %d: %v", n, err)
		}
	}
	for _, n := range []int{-1, api.MaxStopTimeout + 1} {
		s := api.JailSpec{Image: "fb@stable", Boot: api.BootPolicy{StopTimeout: n}}
		if err := JailSpec("web", s); err == nil {
			t.Errorf("stop timeout %d is accepted", n)
		}
	}
}
