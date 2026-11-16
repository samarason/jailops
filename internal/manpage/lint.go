package manpage

import (
	"fmt"
	"regexp"
	"strings"
)

var newSentence = regexp.MustCompile(`[.!?][)\]'"]* +[A-Z]`)

// Lint reports what mandoc -Tlint would remark on a page, as far as it can be told without mandoc: an input
// line longer than 80 bytes, a sentence starting in the middle of a text line, trailing blanks, a tab in filled
// text, a paragraph macro where it would be skipped, and references out of order in SEE ALSO. Tests run it over
// every generated and hand-written page.
func Lint(page string) []string {
	var out []string
	say := func(n int, format string, a ...any) {
		out = append(out, fmt.Sprintf("line %d: ", n)+fmt.Sprintf(format, a...))
	}
	lines := strings.Split(strings.TrimSuffix(page, "\n"), "\n")
	literalBlock, seeAlso := false, false
	var xrs []string
	for i, l := range lines {
		n := i + 1
		tok := strings.Fields(l)
		macro := ""
		if strings.HasPrefix(l, ".") && len(tok) > 0 {
			macro = tok[0]
		}
		switch macro {
		case ".Bd":
			literalBlock = true
		case ".Ed":
			literalBlock = false
		case ".Sh":
			seeAlso = strings.TrimPrefix(l, ".Sh ") == "SEE ALSO"
		}
		// mandoc -Tlint: a macro line that ends in a word with a closing bracket glued to it ("PROJECT]" after
		// "[--project") has no blank before its trailing delimiter; the usage string should not end like that
		if (macro == ".Ar" || macro == ".Nm") && len(tok) > 1 {
			if w := tok[len(tok)-1]; strings.HasSuffix(w, "]") && !strings.HasPrefix(w, "[") {
				say(n, "no blank before trailing delimiter: %q (word the usage so that it does not end in a word and a bracket)", w)
			}
		}
		if len(l) > width {
			say(n, "%d bytes", len(l))
		}
		if strings.TrimRight(l, " \t") != l {
			say(n, "trailing blanks")
		}
		if macro == "" && !literalBlock {
			if strings.Contains(l, "\t") {
				say(n, "tab in filled text")
			}
			if newSentence.MatchString(l) {
				say(n, "new sentence, new line: %q", l)
			}
		}
		if !literalBlock {
			for _, w := range tok {
				if w == "--" {
					say(n, "verbatim --, written as two hyphens")
				}
				if _, ok := osWord(w); ok && macro == "" {
					say(n, "the operating system's name without its macro")
				}
			}
		}
		if macro == ".Pp" {
			next, prev := "", ""
			if i+1 < len(lines) {
				next = firstWord(lines[i+1])
			}
			if i > 0 {
				prev = firstWord(lines[i-1])
			}
			switch {
			case next == ".Bd", next == ".Bl", next == ".It", next == ".Sh", next == ".Ss", next == ".Pp", next == ".El", next == "":
				say(n, "paragraph macro before %s", next)
			case prev == ".Sh", prev == ".Ss":
				say(n, "paragraph macro after %s", prev)
			}
		}
		if seeAlso && macro == ".Xr" && len(tok) >= 3 {
			xrs = append(xrs, tok[2]+" "+tok[1])
			last := i+1 == len(lines) || firstWord(lines[i+1]) != ".Xr"
			if last != (len(tok) == 3) {
				say(n, "reference punctuation")
			}
		}
	}
	for i := 1; i < len(xrs); i++ {
		if xrs[i] < xrs[i-1] {
			out = append(out, fmt.Sprintf("SEE ALSO: %s after %s", xrs[i], xrs[i-1]))
		}
	}
	return out
}

func firstWord(l string) string {
	if f := strings.Fields(l); len(f) > 0 {
		return f[0]
	}
	return ""
}
