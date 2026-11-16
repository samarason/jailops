package cli

import (
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"regexp"
	"strings"
	"syscall"

	"jailops.net/jailops/sdk"
	"jailops.net/jailops/sdk/api"
)

// Exit codes. They are part of the CLI contract and are never renumbered.
const (
	ExitOK          = 0
	ExitFailure     = 1 // transport failure, aborted, cancelled, anything else
	ExitUsage       = 2 // wrong invocation or a request the server found invalid
	ExitAuth        = 3 // unauthorized, forbidden, rate limited
	ExitNotFound    = 4
	ExitConflict    = 5 // already exists, stale, busy, in use
	ExitUnsupported = 6
	ExitInternal    = 7
)

// exitForCode maps an API error code to an exit code.
func exitForCode(c api.Code) int {
	switch c {
	case api.CodeInvalid, api.CodeDataLoss, api.CodeKeyNotEscrowed, api.CodePlaintextDenied:
		return ExitUsage
	case api.CodeUnauthorized, api.CodeForbidden, api.CodeRateLimited, api.CodeBadPassphrase:
		return ExitAuth
	case api.CodeNotFound:
		return ExitNotFound
	case api.CodeAlreadyExists, api.CodeConflict, api.CodeBusy, api.CodeIPConflict,
		api.CodePoolExhausted, api.CodeImageInUse, api.CodeMergeConflict, api.CodeChainBroken,
		api.CodeQuotaExceeded, api.CodeMaintenance, api.CodeMissingChunks, api.CodeLeaseExpired, api.CodeLocked:
		return ExitConflict
	case api.CodeUnsupported, api.CodeUnverified, api.CodeZFSIncompatible, api.CodeVersionSkew, api.CodeNotManaged:
		return ExitUnsupported // not_managed: this host does not let JailOps do it
	case api.CodeInternal, api.CodeNotLeader, api.CodeNoQuorum, api.CodeStopForced:
		return ExitInternal
	}
	return ExitInternal // a code this client does not know is a server matter
}

// exitError carries the exit status of a command run in a jail.
type exitError struct{ code int }

func (e *exitError) Error() string { return fmt.Sprintf("the command exited with status %d", e.code) }

// ExitCode returns the process exit code for err.
func ExitCode(err error) int {
	if err == nil {
		return ExitOK
	}
	var xe *exitError
	if errors.As(err, &xe) {
		return xe.code
	}
	var ue *usageError
	if errors.As(err, &ue) {
		return ExitUsage
	}
	var ae *api.Error
	if errors.As(err, &ae) {
		return exitForCode(ae.Code)
	}
	return ExitFailure
}

// printError writes "code: message" and the hint on a second line.
func (a *app) printError(err error) {
	var xe *exitError
	if errors.As(err, &xe) {
		return // the command's own output said what happened
	}
	w := a.env.Stderr
	red := func(s string) colored { return colored(termText(s, false)) }
	if a.colorOn(w) {
		red = func(s string) colored { return colored("\x1b[31m" + termText(s, false) + "\x1b[0m") }
	}
	var ae *api.Error
	var ue *usageError
	var ab *abortError
	var he *hintError
	switch {
	case errors.As(err, &ae):
		fprintf(w, "%s: %s\n", red(string(ae.Code)), termText(ae.Message, false))
		hint := ae.Hint
		if hint == "" && ae.Code == api.CodeUnauthorized && a.conn != nil && a.conn.URL == "" && a.conn.Token == "" {
			hint = "the local socket knows only root: run this with sudo, or use a token or client certificate (jailops remote add, or JAILOPS_TOKEN)"
		}
		if hint == "" {
			hint = fallbackHint(ae)
		}
		if hint != "" {
			fprintf(w, "hint: %s\n", termText(hint, false))
		}
	case errors.As(err, &ue):
		fprintf(w, "%s: %s\n", red("usage"), ue.err)
		hint := ue.hint
		if hint == "" && a.cmdPath != "" {
			hint = fmt.Sprintf("run '%s --help' for usage", a.cmdPath)
		}
		if hint != "" {
			fprintf(w, "hint: %s\n", termText(hint, false))
		}
	case errors.As(err, &he):
		fprintf(w, "%s: %s\n", red("error"), he.err)
		fprintf(w, "hint: %s\n", he.hint)
	case errors.As(err, &ab):
		fprintf(w, "%s: %s\n", red("aborted"), ab.msg)
	case errors.Is(err, sdk.ErrCancelled):
		fprintf(w, "%s: %s\n", red("cancelled"), err)
	case isTransport(err):
		msg, hint := a.unreachable(err)
		fprintf(w, "%s: %s\n", red("unavailable"), msg)
		fprintf(w, "hint: %s\n", hint)
	default:
		fprintf(w, "%s: %s\n", red("error"), err)
	}
}

// isTransport reports whether err is a failure to reach the daemon (no socket, refused, unreachable, timed out),
// as opposed to an answer of the daemon or a local mistake such as a missing input file.
func isTransport(err error) bool {
	var oe *net.OpError
	return errors.As(err, &oe)
}

// unreachable words a transport failure: what could not be reached, and where to look.
func (a *app) unreachable(err error) (string, string) {
	why := transportCause(err)
	if a.conn == nil {
		return "cannot reach jailopsd: " + why, "is jailopsd running? 'jailops doctor' shows which connection is used"
	}
	if a.conn.URL == "" {
		msg := "cannot reach jailopsd at " + a.conn.Socket + " (" + why + ")"
		switch {
		case errors.Is(err, syscall.EACCES):
			return msg, "check the permissions of the socket and its directory, or reach the daemon with a token or certificate (--remote)"
		default:
			return msg, "is jailopsd running? Check with 'service jailopsd status'; use --remote to reach another host"
		}
	}
	where := a.conn.URL
	if a.conn.Name != "" && a.conn.Name != a.conn.URL {
		where += " (remote " + a.conn.Name + ")"
	}
	return "cannot reach jailopsd at " + where + " (" + why + ")",
		"check the address ('jailops remote list'), that jailopsd listens there and that a firewall lets you in"
}

// transportCause is the reason of a transport failure in a few words.
func transportCause(err error) string {
	var oe *net.OpError
	switch {
	case errors.Is(err, syscall.ENOENT):
		return "no such socket"
	case errors.Is(err, syscall.EACCES):
		return "permission denied"
	case errors.Is(err, syscall.ECONNREFUSED):
		return "connection refused"
	case errors.Is(err, os.ErrDeadlineExceeded):
		return "timed out"
	case errors.As(err, &oe) && oe.Err != nil:
		return oe.Err.Error()
	}
	return err.Error()
}

// notFoundRe reads the kind and the name out of the server's "<kind> "<name>" not found".
var notFoundRe = regexp.MustCompile(`^([a-z][a-z -]*) "([^"]*)" not found`)

// listCommands are the commands that list each kind the server names in a not_found error.
var listCommands = map[string]string{
	"jail": "jailops jail list", "image": "jailops image list", "network": "jailops network list",
	"project": "jailops project list", "storage": "jailops storage list", "profile": "jailops profile list",
	"user": "jailops user list", "token": "jailops token list", "certificate": "jailops cert list",
	"host": "jailops host list", "operation": "jailops op list", "backup": "jailops backup list",
	"backup-policy": "jailops backup policy list", "backup-target": "jailops backup target list",
	"firewall-policy": "jailops firewall policy list", "address-set": "jailops firewall address-set list",
	"session": "jailops sessions list", "wireguard": "jailops wireguard list",
	"snapshot": "jailops jail snapshot list JAIL", "generation": "jailops image generation list IMAGE",
	"peer": "jailops wireguard peer list TUNNEL", "app": "jailops app list",
}

// fallbackHint is the hint of an error the server sent without one. Codes whose cause is in the message
// (invalid) get none: a generic hint there points the wrong way.
func fallbackHint(ae *api.Error) string {
	switch ae.Code {
	case api.CodeInvalid:
		return ""
	case api.CodeNotFound:
		if m := notFoundRe.FindStringSubmatch(ae.Message); m != nil {
			if cmd, ok := listCommands[m[1]]; ok {
				return "list them with '" + cmd + "'; check --project, --host and --remote too"
			}
		}
	case api.CodeConflict:
		if !strings.Contains(ae.Message, "changed") {
			return ""
		}
		return "someone changed it after you read it: read it again and repeat the change ('edit' commands do this for you)"
	case api.CodeForbidden:
		if strings.Contains(ae.Message, "not granted") {
			return ""
		}
		return "your role or scope does not allow this: ask an administrator ('jailops whoami' shows yours)"
	}
	if e, ok := explainFor(ae.Code); ok && e.Fix != "" {
		return e.Fix + " (jailops explain " + string(ae.Code) + ")"
	}
	return ""
}

// errOut writes a line to w, ignoring errors (a closed pipe is not our failure).
// fprintln and fprintf print human output: every value goes through termText (the format is the CLI's own).
func fprintln(w io.Writer, a ...any)          { _, _ = fmt.Fprintln(w, termArgs(a)...) }
func fprintf(w io.Writer, f string, a ...any) { _, _ = fmt.Fprintf(w, f, termArgs(a)...) }
