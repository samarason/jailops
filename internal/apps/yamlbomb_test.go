package apps

import (
	"strings"
	"testing"
	"time"
)

// A definition is untrusted input: an alias bomb or a deeply nested document is refused quickly, not expanded.
func TestParseRefusesAliasBombsAndDeepNesting(t *testing.T) {
	bomb := `version: 1
name: x
summary: [&a [lol,lol,lol,lol,lol,lol,lol,lol,lol], &b [*a,*a,*a,*a,*a,*a,*a,*a,*a], &c [*b,*b,*b,*b,*b,*b,*b,*b,*b], &d [*c,*c,*c,*c,*c,*c,*c,*c,*c], &e [*d,*d,*d,*d,*d,*d,*d,*d,*d], &f [*e,*e,*e,*e,*e,*e,*e,*e,*e], &g [*f,*f,*f,*f,*f,*f,*f,*f,*f], &h [*g,*g,*g,*g,*g,*g,*g,*g,*g], &i [*h,*h,*h,*h,*h,*h,*h,*h,*h]]
`
	for name, doc := range map[string]string{"alias bomb": bomb, "deep nesting": strings.Repeat("[", 100000)} {
		start := time.Now()
		if _, err := Parse("x", []byte(doc)); err == nil {
			t.Errorf("%s: accepted", name)
		}
		if d := time.Since(start); d > 5*time.Second {
			t.Errorf("%s: took %v", name, d)
		}
	}
}
