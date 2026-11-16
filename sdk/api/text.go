package api

import (
	"strings"
	"unicode"
	"unicode/utf8"
)

// Rules for the text a client stores and other people read: labels, descriptions and comments. What a terminal or a
// page would act on (escape sequences, other control characters, characters that reverse or hide text) is refused.

const (
	// MaxLabels is the most labels one object carries.
	MaxLabels = 64
	// MaxLabelName is the longest name part of a label key, MaxLabelPrefix the longest prefix before a "/".
	MaxLabelName   = 63
	MaxLabelPrefix = 253
	// MaxLabelValue is the longest label value, in bytes.
	MaxLabelValue = 253
	// MaxFreeText is the longest description or comment, in bytes.
	MaxFreeText = 4096
)

// UnsafeRune reports a character that changes how text is shown instead of being shown: the C0 and C1 controls and
// DEL, the bidirectional controls (U+200E, U+200F, U+202A to U+202E, U+2066 to U+2069), the zero-width characters
// that can hide text (U+200B to U+200D, U+2060, U+FEFF). Tab and line feed are controls too; callers that allow
// them check for them first.
func UnsafeRune(r rune) bool {
	switch {
	case unicode.IsControl(r):
		return true
	case r == 0x200e || r == 0x200f, r >= 0x202a && r <= 0x202e, r >= 0x2066 && r <= 0x2069:
		return true
	case r >= 0x200b && r <= 0x200d, r == 0x2060, r == 0xfeff:
		return true
	}
	return false
}

// HasUnsafeText reports text that is not valid UTF-8 or holds an UnsafeRune other than the ones allowed.
func HasUnsafeText(s, allowed string) bool {
	if !utf8.ValidString(s) {
		return true
	}
	for _, r := range s {
		if UnsafeRune(r) && !strings.ContainsRune(allowed, r) {
			return true
		}
	}
	return false
}

func labelNameOK(s string, max int, extra string) bool {
	if s == "" || len(s) > max {
		return false
	}
	alnum := func(c byte) bool { return c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' }
	if !alnum(s[0]) || !alnum(s[len(s)-1]) {
		return false
	}
	for i := 0; i < len(s); i++ {
		if c := s[i]; !alnum(c) && !strings.ContainsRune(extra, rune(c)) {
			return false
		}
	}
	return true
}

// ValidLabelKey checks a label key: a name of at most 63 characters (letters, digits, "-", "_" and ".", beginning and
// ending with a letter or digit), with an optional prefix of at most 253 characters and a "/" before it ("jailops.app",
// "example.org/tier").
func ValidLabelKey(k string) error {
	prefix, name, hasPrefix := strings.Cut(k, "/")
	if !hasPrefix {
		name, prefix = prefix, ""
	}
	if !labelNameOK(name, MaxLabelName, "-_.") || (hasPrefix && !labelNameOK(prefix, MaxLabelPrefix, "-.")) {
		return Errorf(CodeInvalid, "invalid label key %q", truncateQuoted(k)).
			WithHint("letters, digits, '-', '_' and '.', beginning and ending with a letter or digit, at most 63 characters, with an optional prefix and '/' (example.org/tier)")
	}
	return nil
}

// ValidLabels checks the labels of an object: at most MaxLabels, valid keys, values of at most MaxLabelValue bytes of
// printable UTF-8.
func ValidLabels(labels map[string]string) error {
	if len(labels) > MaxLabels {
		return Errorf(CodeInvalid, "an object has at most %d labels (got %d)", MaxLabels, len(labels))
	}
	for k, v := range labels {
		if err := ValidLabelKey(k); err != nil {
			return err
		}
		if len(v) > MaxLabelValue {
			return Errorf(CodeInvalid, "the value of label %q is longer than %d bytes", k, MaxLabelValue)
		}
		if HasUnsafeText(v, "") {
			return Errorf(CodeInvalid, "the value of label %q holds control or invisible characters", k).
				WithHint("label values are printable text")
		}
	}
	return nil
}

// ValidFreeText checks a description or comment: at most MaxFreeText bytes of valid UTF-8 without control or
// invisible characters (a line break and a tab are allowed where multiline says so).
func ValidFreeText(field, s string, multiline bool) error {
	if len(s) > MaxFreeText {
		return Errorf(CodeInvalid, "%s is longer than %d bytes", field, MaxFreeText)
	}
	allowed := ""
	if multiline {
		allowed = "\n\t"
	}
	if HasUnsafeText(s, allowed) {
		return Errorf(CodeInvalid, "%s holds control or invisible characters", field)
	}
	return nil
}

// Commented is a specification that carries a comment, one line of free text about what the object is for.
type Commented interface{ CommentText() string }

// CheckComment validates the comment of a specification that has one.
func CheckComment(spec any) error {
	if c, ok := spec.(Commented); ok {
		return ValidFreeText("comment", c.CommentText(), false)
	}
	return nil
}

// truncateQuoted shortens a value for an error message.
func truncateQuoted(s string) string {
	if len(s) > 80 {
		return strings.ToValidUTF8(s[:80], "") + "..."
	}
	return s
}
