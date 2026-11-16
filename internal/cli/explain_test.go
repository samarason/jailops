package cli

import (
	"go/ast"
	"go/parser"
	"go/token"
	"strconv"
	"testing"

	"jailops.net/jailops/sdk/api"
)

// codesInSource lists every constant of type Code declared in sdk/api/errors.go.
func codesInSource(t *testing.T) []api.Code {
	t.Helper()
	f, err := parser.ParseFile(token.NewFileSet(), "../../sdk/api/errors.go", nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	var out []api.Code
	for _, d := range f.Decls {
		gd, ok := d.(*ast.GenDecl)
		if !ok || gd.Tok != token.CONST {
			continue
		}
		for _, sp := range gd.Specs {
			vs := sp.(*ast.ValueSpec)
			id, ok := vs.Type.(*ast.Ident)
			if !ok || id.Name != "Code" {
				continue
			}
			for _, v := range vs.Values {
				if lit, ok := v.(*ast.BasicLit); ok && lit.Kind == token.STRING {
					s, _ := strconv.Unquote(lit.Value)
					out = append(out, api.Code(s))
				}
			}
		}
	}
	return out
}

func TestExplainCoversEveryCode(t *testing.T) {
	codes := codesInSource(t)
	if len(codes) < 20 {
		t.Fatalf("found only %d codes in errors.go; the parser is wrong", len(codes))
	}
	seen := map[api.Code]bool{}
	for _, e := range explanations {
		if seen[e.Code] {
			t.Errorf("duplicate explanation for %s", e.Code)
		}
		seen[e.Code] = true
		if e.Cause == "" || e.Fix == "" {
			t.Errorf("%s: cause and fix are required", e.Code)
		}
	}
	for _, c := range codes {
		if !seen[c] {
			t.Errorf("api code %q has no explanation: add it to explanations in explain.go", c)
		}
		delete(seen, c)
	}
	for c := range seen {
		t.Errorf("explanation for %q, which is not an api code", c)
	}
}

// Documented exit statuses, written out independently of the code.
func TestExitCodesPerAPICode(t *testing.T) {
	want := map[api.Code]int{
		api.CodeInvalid: ExitUsage, api.CodeDataLoss: ExitUsage, api.CodeKeyNotEscrowed: ExitUsage, api.CodePlaintextDenied: ExitUsage,
		api.CodeUnauthorized: ExitAuth, api.CodeForbidden: ExitAuth, api.CodeRateLimited: ExitAuth, api.CodeBadPassphrase: ExitAuth, api.CodeNotManaged: ExitUnsupported,
		api.CodeNotFound:      ExitNotFound,
		api.CodeAlreadyExists: ExitConflict, api.CodeConflict: ExitConflict, api.CodeBusy: ExitConflict, api.CodeIPConflict: ExitConflict,
		api.CodeQuotaExceeded: ExitConflict, api.CodeMaintenance: ExitConflict, api.CodeMissingChunks: ExitConflict, api.CodeLeaseExpired: ExitConflict, api.CodeLocked: ExitConflict,
		api.CodePoolExhausted: ExitConflict, api.CodeImageInUse: ExitConflict, api.CodeMergeConflict: ExitConflict, api.CodeChainBroken: ExitConflict,
		api.CodeUnsupported: ExitUnsupported, api.CodeUnverified: ExitUnsupported, api.CodeZFSIncompatible: ExitUnsupported, api.CodeVersionSkew: ExitUnsupported,
		api.CodeInternal: ExitInternal, api.CodeNotLeader: ExitInternal, api.CodeNoQuorum: ExitInternal, api.CodeStopForced: ExitInternal,
	}
	for _, c := range codesInSource(t) {
		w, ok := want[c]
		if !ok {
			t.Errorf("code %s has no documented exit status in this test", c)
			continue
		}
		if got := exitForCode(c); got != w {
			t.Errorf("%s: exit %d, want %d", c, got, w)
		}
		if got := ExitCode(api.Errorf(c, "x")); got != w {
			t.Errorf("%s via ExitCode: %d", c, got)
		}
	}
	distinct := map[int]bool{ExitUsage: true, ExitAuth: true, ExitNotFound: true, ExitConflict: true, ExitUnsupported: true, ExitInternal: true, ExitFailure: true}
	if len(distinct) != 7 {
		t.Fatal("exit codes are not distinct")
	}
}
