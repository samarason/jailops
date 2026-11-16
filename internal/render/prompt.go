package render

import (
	"fmt"
	"strings"

	"jailops.net/jailops/sdk/api"
)

// The bash prompt of a FreeBSD jail (docs/shell.md): two files JailOps owns, api.EnvFile (the variables that say where
// the jail is, EnvScript) and api.PromptFile, and a marked block at the top of the two system start-up files of the
// FreeBSD bash package that sources them.

// EnvScript is the text of api.EnvFile. It is the same in every jail: the host starts a jail with the parameters
// env.jailops_jail, env.jailops_project and env.jailops_host (JailConf), which the jail reads as the lines key=value
// of the read-only sysctl security.jail.env, and the script exports them as JAILOPS_JAIL, JAILOPS_PROJECT and
// JAILOPS_HOST in the shell that sources it. Any tool may write that buffer, so only a line whose key is one of the
// three names is used, and only when its
// value is made of lower-case letters, digits and hyphens (the letters are spelled out, so no locale widens the
// range): nothing a value holds can be run or end an assignment. It is POSIX sh and runs one sysctl when a shell
// starts.
func EnvScript() string {
	return `# Managed by JailOps: where this jail is. The same text in every jail (jailops jail shell-setup JAIL writes it).
# The host starts the jail with the parameters env.jailops_jail, env.jailops_project and env.jailops_host; here they
# are lines key=value of the sysctl security.jail.env (sysctl -n security.jail.env), and this file exports those three.
while IFS='=' read -r _jailops_k _jailops_v; do
	case "$_jailops_v" in '' | *[!abcdefghijklmnopqrstuvwxyz0123456789-]*) continue ;; esac
	case "$_jailops_k" in
	jailops_jail) JAILOPS_JAIL=$_jailops_v; export JAILOPS_JAIL ;;
	jailops_project) JAILOPS_PROJECT=$_jailops_v; export JAILOPS_PROJECT ;;
	jailops_host) JAILOPS_HOST=$_jailops_v; export JAILOPS_HOST ;;
	esac
done <<JAILOPS_ENV
$(sysctl -n security.jail.env 2>/dev/null)
JAILOPS_ENV
unset _jailops_k _jailops_v
`
}

// PromptFile renders api.PromptFile for the PS1 text ps1 (api.EffectivePS1). The text must pass api.CheckPS1: it
// is written as a single-quoted assignment, and the check guarantees that it holds only the references to the
// three variables of EnvScript, the tag of the default prompt and text api.CheckPrompt accepts: no single quote,
// no line break and nothing bash would run when it expands the prompt. The assignment is made only in an
// interactive bash, so sh, scripts and `bash -c` are not affected.
func PromptFile(ps1 string) (string, error) {
	if ps1 == api.PromptDefault || ps1 == api.PromptShort || ps1 == api.PromptNone {
		return "", fmt.Errorf("render: %q is a prompt value, not a PS1 text", ps1)
	}
	if err := api.CheckPS1(ps1); err != nil {
		return "", fmt.Errorf("render: %w", err)
	}
	// belt and braces: CheckPS1 refuses all of these
	if strings.ContainsAny(ps1, "'\n\r\x00`") {
		return "", fmt.Errorf("render: the prompt holds a quote or a line break")
	}
	var b strings.Builder
	b.WriteString("# Managed by JailOps: the bash prompt of this jail. JailOps rewrites this file;\n")
	b.WriteString("# change the prompt with: jailops config set JAIL prompt default|short|none|PS1\n")
	b.WriteString("# Your own ~/.bashrc, ~/.bash_profile or ~/.profile is read after this file and wins.\n")
	b.WriteString("# Only an interactive bash sets the prompt; sh, scripts and bash -c are not affected.\n")
	b.WriteString("if [ -n \"${BASH_VERSION-}\" ] && [ -n \"${PS1-}\" ]; then\n")
	if api.PromptUsesWhere(ps1) {
		b.WriteString("\t" + api.WhereLine() + "\n")
	}
	b.WriteString("\tPS1='" + ps1 + "'\n")
	b.WriteString("fi\n")
	return b.String(), nil
}

// The marked block that sources api.EnvFile and, when the jail has a prompt, api.PromptFile.
const (
	promptBegin = "# BEGIN jailops shell: managed by JailOps (jailops config set JAIL prompt none keeps the variables and drops the prompt)"
	promptEnd   = "# END jailops shell"
)

func promptBlock(withPrompt bool) string {
	b := promptBegin + "\n" +
		"if [ -r " + api.EnvFile + " ]; then . " + api.EnvFile + "; fi\n"
	if withPrompt {
		b += "if [ -r " + api.PromptFile + " ]; then . " + api.PromptFile + "; fi\n"
	}
	return b + promptEnd + "\n"
}

// splitPromptBlock returns existing without the marked block, and whether there was one. A begin line without
// an end line is an error: the file was edited by hand and is left alone.
func splitPromptBlock(existing string) (string, bool, error) {
	lines := strings.SplitAfter(existing, "\n")
	var out strings.Builder
	found, in := false, false
	for _, l := range lines {
		t := strings.TrimRight(l, "\n")
		switch {
		case !in && strings.HasPrefix(t, "# BEGIN jailops shell"):
			if found {
				return "", false, fmt.Errorf("render: the file has two jailops shell blocks")
			}
			in, found = true, true
		case in && t == promptEnd:
			in = false
		case in:
		default:
			out.WriteString(l)
		}
	}
	if in {
		return "", false, fmt.Errorf("render: the jailops shell block has no end line (%q)", promptEnd)
	}
	return out.String(), found, nil
}

// PromptHookSet returns existing (the content of api.ProfilePath or api.BashrcPath, empty when the file does not
// exist) with the marked block at its top, so the file's own lines and the user's start-up files come after it
// and win. A block that is there already is replaced; every other line is kept as it is.
func PromptHookSet(existing string, withPrompt bool) (string, error) {
	rest, _, err := splitPromptBlock(existing)
	if err != nil {
		return "", err
	}
	return promptBlock(withPrompt) + rest, nil
}
