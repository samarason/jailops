package model

import (
	"reflect"
	"strings"
	"testing"
	"time"

	"jailops.net/jailops/sdk/api"
)

func TestMergeFollowsRFC7386(t *testing.T) {
	dst := map[string]any{"a": 1, "m": map[string]any{"x": 1, "y": 2}, "l": []any{1, 2}, "gone": "x"}
	src := map[string]any{"a": 2, "m": map[string]any{"y": 3, "z": 4}, "l": []any{9}, "gone": nil}
	got := Merge(dst, src)
	want := map[string]any{"a": 2, "m": map[string]any{"x": 1, "y": 3, "z": 4}, "l": []any{9}}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %v want %v", got, want)
	}
}

func TestMergeDoesNotAliasSource(t *testing.T) {
	tmpl := map[string]any{"m": map[string]any{"x": 1}}
	a := Merge(map[string]any{}, CloneMap(tmpl))
	a["m"].(map[string]any)["x"] = 99
	if tmpl["m"].(map[string]any)["x"] != 1 {
		t.Fatal("the template was modified through a merged copy")
	}
}

func TestDecodeStrictRejectsUnknownKeys(t *testing.T) {
	_, err := DecodeSpec(api.KindJail, map[string]any{"image": "i", "imge": "typo"})
	if err == nil || !strings.Contains(err.Error(), "imge") {
		t.Fatalf("got %v", err)
	}
	if _, err := DecodeSpec(api.KindRemote, map[string]any{}); err == nil {
		t.Fatal("an unmanaged kind decoded")
	}
}

func TestNames(t *testing.T) {
	for _, ok := range []string{"a", "web-1"} {
		if err := CheckName(ok); err != nil {
			t.Errorf("%q: %v", ok, err)
		}
	}
	for _, bad := range []string{"", "A", "-a", ".a", "a b", "a/b", "x_y.z", "0day", "web-", strings.Repeat("a", 64)} {
		if CheckName(bad) == nil {
			t.Errorf("%q accepted", bad)
		}
	}
	if CheckSimpleName("a.b") == nil {
		t.Error("dots allowed in simple names")
	}
}

func TestRolloutSpec(t *testing.T) {
	r := RolloutSpec{Selector: map[string]string{"a": "b"}, Pause: "30s", HealthGate: HealthGate{Timeout: "1m"}}
	if err := r.Validate(); err != nil {
		t.Fatal(err)
	}
	p, to, iv, _ := r.Durations()
	if p != 30*time.Second || to != time.Minute || iv != 2*time.Second {
		t.Fatalf("%v %v %v", p, to, iv)
	}
	for name, bad := range map[string]RolloutSpec{
		"no selector": {},
		"action":      {Selector: map[string]string{"a": "b"}, Action: "delete"},
		"generation":  {Selector: map[string]string{"a": "b"}, Generation: "3"},
		"duration":    {Selector: map[string]string{"a": "b"}, Pause: "soon"},
		"negative":    {Selector: map[string]string{"a": "b"}, Canary: -1},
	} {
		if bad.Validate() == nil {
			t.Errorf("%s accepted", name)
		}
	}
}
