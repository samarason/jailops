package cli

import (
	"fmt"
	"reflect"
	"strings"
	"unicode/utf8"

	"jailops.net/jailops/sdk/api"
)

// What a server sends (names, labels, messages, hints, audit entries, certificate subjects) is printed on the
// user's terminal, and a terminal acts on control characters: an escape sequence can set the window title, clear the
// screen, hide text or move the cursor over a line already printed. Every value the human output prints passes
// through termText; JSON and YAML output stay as the server sent them (escaped by their encoders).

// colored is text the CLI built itself, with its own colour sequences around values that termText already
// cleaned. It is printed as it is.
type colored string

// termText makes text safe to print on a terminal: control characters (C0, DEL, C1, escape sequences included),
// bidirectional controls and zero-width characters become U+FFFD, and so do bytes that are not UTF-8. Tab stays, line
// feed only when multiline is set.
func termText(s string, multiline bool) string {
	clean := true
	for i := 0; i < len(s); i++ {
		if c := s[i]; c < 0x20 && c != '\t' || c == 0x7f || c >= 0x80 {
			clean = false
			break
		}
	}
	if clean {
		return s
	}
	var b strings.Builder
	for i := 0; i < len(s); {
		r, n := utf8.DecodeRuneInString(s[i:])
		switch {
		case r == utf8.RuneError && n == 1:
			b.WriteRune(utf8.RuneError)
		case r == '\t', r == '\n' && multiline:
			b.WriteRune(r)
		case api.UnsafeRune(r):
			b.WriteRune(utf8.RuneError)
		default:
			b.WriteString(s[i : i+n])
		}
		i += n
	}
	return b.String()
}

// termArgs passes the values of a Printf call through termText (multiline: a value that is a block of text keeps
// its lines; single-line fields are cleaned where they are built).
func termArgs(args []any) []any {
	out := make([]any, len(args))
	for i, a := range args {
		out[i] = termValue(a)
	}
	return out
}

func termValue(a any) any {
	switch v := a.(type) {
	case nil:
		return nil
	case colored:
		return string(v)
	case string:
		return termText(v, true)
	case []byte:
		return termText(string(v), true)
	case error:
		return termText(v.Error(), true)
	case fmt.Stringer:
		return termText(v.String(), true)
	case []string:
		c := make([]string, len(v))
		for i, s := range v {
			c[i] = termText(s, true)
		}
		return c
	}
	if rv := reflect.ValueOf(a); rv.Kind() == reflect.String {
		return termText(rv.String(), true)
	}
	return a
}
