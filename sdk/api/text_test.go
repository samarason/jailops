package api

import (
	"encoding/json"
	"os"
	"strconv"
	"strings"
	"testing"
)

// labelCases reads testdata/labels.json, which the host console's tests read too: both sides check the same keys and
// values.
func labelCases(t *testing.T) (keys, values map[string][]string) {
	t.Helper()
	b, err := os.ReadFile("testdata/labels.json")
	if err != nil {
		t.Fatal(err)
	}
	var f struct {
		Keys, Values map[string][][]json.RawMessage
	}
	if err := json.Unmarshal(b, &f); err != nil {
		t.Fatal(err)
	}
	build := func(in map[string][][]json.RawMessage) map[string][]string {
		out := map[string][]string{}
		for kind, cases := range in {
			for _, parts := range cases {
				var sb strings.Builder
				for _, p := range parts {
					var s string
					if json.Unmarshal(p, &s) == nil {
						sb.WriteString(s)
						continue
					}
					var rep []json.RawMessage
					var n int
					if err := json.Unmarshal(p, &rep); err != nil || len(rep) != 2 || json.Unmarshal(rep[0], &s) != nil || json.Unmarshal(rep[1], &n) != nil {
						t.Fatalf("bad part %s", p)
					}
					sb.WriteString(strings.Repeat(s, n))
				}
				out[kind] = append(out[kind], sb.String())
			}
		}
		return out
	}
	return build(f.Keys), build(f.Values)
}

func TestLabelRulesFixture(t *testing.T) {
	keys, values := labelCases(t)
	if len(keys["valid"]) == 0 || len(keys["invalid"]) == 0 || len(values["valid"]) == 0 || len(values["invalid"]) == 0 {
		t.Fatal("the fixture has no cases")
	}
	for _, k := range keys["valid"] {
		if err := ValidLabelKey(k); err != nil {
			t.Errorf("key %q: %v", k, err)
		}
	}
	for _, k := range keys["invalid"] {
		if ValidLabelKey(k) == nil {
			t.Errorf("key %q was accepted", k)
		}
	}
	for _, v := range values["valid"] {
		if err := ValidLabels(map[string]string{"k": v}); err != nil {
			t.Errorf("value %q: %v", v, err)
		}
	}
	for _, v := range values["invalid"] {
		if ValidLabels(map[string]string{"k": v}) == nil {
			t.Errorf("value %q was accepted", v)
		}
	}
	many := map[string]string{}
	for i := 0; i < MaxLabels+1; i++ {
		many["k"+strconv.Itoa(i)] = ""
	}
	if ValidLabels(many) == nil {
		t.Errorf("%d labels were accepted", len(many))
	}
}
