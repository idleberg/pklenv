package config

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/idleberg/pklenv/internal/redact"
)

// requirePkl skips when the pkl CLI is absent. pkl-go works by spawning
// `pkl server`, so these are genuine integration tests against the real
// evaluator — there is no meaningful way to fake it, and a fake would not
// catch the schema drift these tests exist to catch.
func requirePkl(t *testing.T) {
	t.Helper()
	if _, err := exec.LookPath("pkl"); err != nil {
		t.Skip("pkl not on PATH; run under `mise exec` or `mise run test`")
	}
}

func TestLoadNormalizesValues(t *testing.T) {
	requirePkl(t)

	cfg, err := Load(context.Background(), "testdata/env.pkl", Options{})
	if err != nil {
		t.Fatal(err)
	}

	// Non-string scalars are stringified by the schema, since environment
	// variables are strings at the OS level regardless.
	want := map[string]string{
		"NODE_ENV":      "production",
		"PORT":          "8080",
		"DEBUG":         "false",
		"API_TOKEN":     "tok_abcdef123456",
		"LEGACY_SECRET": "not-really",
		"EXTRA":         "masked-anyway",
	}
	for name, wantVal := range want {
		if got := cfg.Vars[name].Value; got != wantVal {
			t.Errorf("%s = %q, want %q", name, got, wantVal)
		}
	}
}

func TestLoadDecisions(t *testing.T) {
	requirePkl(t)

	cfg, err := Load(context.Background(), "testdata/env.pkl", Options{})
	if err != nil {
		t.Fatal(err)
	}

	want := map[string]redact.Decision{
		"API_TOKEN":     redact.Redacted,   // matched by the *_TOKEN glob
		"EXTRA":         redact.Redacted,   // explicit redact = true
		"LEGACY_SECRET": redact.Waived,     // explicit redact = false
		"NODE_ENV":      redact.Undeclared, // no rule touches it
	}
	for name, wantD := range want {
		if got := cfg.Decisions[name]; got != wantD {
			t.Errorf("decision for %s = %v, want %v", name, got, wantD)
		}
	}
}

func TestSecretValues(t *testing.T) {
	requirePkl(t)

	cfg, err := Load(context.Background(), "testdata/env.pkl", Options{})
	if err != nil {
		t.Fatal(err)
	}

	got := strings.Join(cfg.SecretValues(), ",")
	for _, want := range []string{"tok_abcdef123456", "masked-anyway"} {
		if !strings.Contains(got, want) {
			t.Errorf("SecretValues() = %v, want it to contain %q", got, want)
		}
	}
	// A waived variable is explicitly not masked.
	if strings.Contains(got, "not-really") {
		t.Errorf("SecretValues() = %v, want the waived value excluded", got)
	}
}

func TestNamesAreSorted(t *testing.T) {
	requirePkl(t)

	cfg, err := Load(context.Background(), "testdata/env.pkl", Options{})
	if err != nil {
		t.Fatal(err)
	}

	names := cfg.Names()
	for i := 1; i < len(names); i++ {
		if names[i-1] > names[i] {
			t.Fatalf("Names() not sorted: %v", names)
		}
	}
}

// Merging happens only through Pkl's own `amends`, never by pklenv joining
// files itself.
func TestLoadFollowsAmends(t *testing.T) {
	requirePkl(t)

	cfg, err := Load(context.Background(), "testdata/env.production.pkl", Options{})
	if err != nil {
		t.Fatal(err)
	}

	if got := cfg.Vars["TIER"].Value; got != "prod" {
		t.Errorf("TIER = %q, want prod (declared in the amending file)", got)
	}
	if got := cfg.Vars["PORT"].Value; got != "8080" {
		t.Errorf("PORT = %q, want 8080 (inherited through amends)", got)
	}
	// Redaction globs are inherited too, or the amending file would silently
	// lose its parent's masking.
	if got := cfg.Decisions["API_TOKEN"]; got != redact.Redacted {
		t.Errorf("API_TOKEN decision = %v, want Redacted through amends", got)
	}
}

// Reading the environment needs no grant. The allowlist that used to gate this
// was removed: it covered env: alone while leaving file: reads and remote
// package: imports open, so it implied a protection it did not provide.
func TestLoadReadsEnvWithoutAGrant(t *testing.T) {
	requirePkl(t)

	cfg, err := Load(context.Background(), "testdata/env.secretread.pkl", Options{
		Env: []string{"PKLENV_TEST_SECRET=from-the-environment"},
	})
	if err != nil {
		t.Fatal(err)
	}

	if got := cfg.Vars["PKLENV_TEST_SECRET"].Value; got != "from-the-environment" {
		t.Errorf("got %q, want the value read from the environment", got)
	}
}

// Selection is expressed in Pkl now, via a glob read. This is the replacement
// for the allowlist, so it is worth holding in place with a test.
func TestLoadBulkReadSelectsByPrefix(t *testing.T) {
	requirePkl(t)

	cfg, err := Load(context.Background(), "testdata/env.bulkread.pkl", Options{
		Env: []string{
			"PKLENV_BULK_ONE=first",
			"PKLENV_BULK_TWO=second",
			"PKLENV_OTHER=excluded",
		},
	})
	if err != nil {
		t.Fatal(err)
	}

	if got := cfg.Vars["PKLENV_BULK_ONE"].Value; got != "first" {
		t.Errorf("PKLENV_BULK_ONE = %q, want first", got)
	}
	if got := cfg.Vars["PKLENV_BULK_TWO"].Value; got != "second" {
		t.Errorf("PKLENV_BULK_TWO = %q, want second", got)
	}
	if _, present := cfg.Vars["PKLENV_OTHER"]; present {
		t.Error("a name outside the pattern must not be selected")
	}
}

// An unset variable now fails as what it is. Under the old allowlist this was
// indistinguishable from a denial, because ungranted names were simply absent
// from the evaluator's environment.
func TestLoadUnsetVariableSaysSo(t *testing.T) {
	requirePkl(t)

	_, err := Load(context.Background(), "testdata/env.unset.pkl", Options{
		Env: []string{"UNRELATED=1"},
	})
	if err == nil {
		t.Fatal("expected an error for a read of an unset variable")
	}
	if !strings.Contains(err.Error(), "Cannot find resource") {
		t.Errorf("the error should say the resource is missing: %v", err)
	}
}

// The schema constrains the key type, so a malformed name fails at the line
// that declares it rather than later in the CLI.
func TestLoadRejectsMalformedVariableName(t *testing.T) {
	requirePkl(t)

	dir := t.TempDir()
	schema, err := filepath.Abs("../../pkl/PklEnv.pkl")
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "env.pkl")
	body := "amends \"" + schema + "\"\n\nvars {\n  [\"BAD-NAME\"] = \"dash\"\n}\n"
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}

	_, err = Load(context.Background(), path, Options{})
	if err == nil {
		t.Fatal("expected a malformed variable name to fail evaluation")
	}
	if !strings.Contains(err.Error(), "BAD-NAME") {
		t.Errorf("the error should name the offending key: %v", err)
	}
}

// Hint matches the literal EnvName pattern in Pkl's diagnostic text, which is a
// copy of the one in the schema. A test built from a hand-written message would
// keep passing after the schema's regex changed — the hint would simply stop
// appearing for real configs. So this one goes through a real evaluation.
func TestHintFiresOnTheRealDiagnostic(t *testing.T) {
	requirePkl(t)

	_, err := Load(context.Background(), "testdata/env.badname.pkl", Options{})
	if err == nil {
		t.Fatal("expected a malformed variable name to fail evaluation")
	}

	var evalErr *EvalError
	if !errors.As(err, &evalErr) {
		t.Fatalf("expected an *EvalError, got %T: %v", err, err)
	}
	if !strings.Contains(evalErr.Hint(), "cannot start with a digit") {
		t.Errorf("the name hint did not fire; the pattern in Hint has drifted from "+
			"EnvName in pkl/PklEnv.pkl. Diagnostic was:\n%v", err)
	}
}

func TestLoadMissingFile(t *testing.T) {
	_, err := Load(context.Background(), "testdata/does-not-exist.pkl", Options{})
	if err == nil {
		t.Fatal("expected an error for a missing file")
	}
}

// Pkl's diagnostics quote source, and source can contain values. The summary
// keeps the classification and drops everything that could carry one.
func TestEvalErrorSummaryDropsValues(t *testing.T) {
	full := errors.New(`–– Pkl Error ––
Type constraint ` + "`length > 100`" + ` violated.
Value: "tok_supersecret"

6 | ["API_TOKEN"] = "tok_supersecret" as String(length > 100)
                                       ^^^^^^^^^^^^`)

	e := &EvalError{File: "env.pkl", Err: full}

	got := e.Summary()
	if strings.Contains(got, "tok_supersecret") {
		t.Fatalf("summary leaked the value: %q", got)
	}
	if !strings.Contains(got, "Type constraint") {
		t.Errorf("summary should keep the classification, got %q", got)
	}
	if !strings.Contains(got, "env.pkl") {
		t.Errorf("summary should name the file, got %q", got)
	}
	// The full error stays available for the verbose path.
	if !strings.Contains(e.Error(), "tok_supersecret") {
		t.Error("Error() should still carry the full diagnostic")
	}
}

// A diagnostic with no blank line separating the excerpt must still not fall
// back to printing everything.
func TestEvalErrorSummaryHandlesUnexpectedShape(t *testing.T) {
	e := &EvalError{File: "env.pkl", Err: errors.New(`Value: "s3cr3t"`)}
	if got := e.Summary(); strings.Contains(got, "s3cr3t") {
		t.Fatalf("summary leaked the value: %q", got)
	}
}

// Each hint is matched against a real diagnostic, so the patterns are asserted
// against the text Pkl actually produces rather than a paraphrase.
func TestEvalErrorHints(t *testing.T) {
	cases := []struct {
		name string
		msg  string
		want string
	}{
		{"unset resource", "Cannot find resource `env:NOPE`.", "read?("},
		{"bad amends", "Cannot find module `file:///tmp/nope/PklEnv.pkl`.", "relative to this file"},
		{"bad property", "Cannot find property `redaction` in module `pklenv.PklEnv`.", "schema this config amends"},
		{
			"bad variable name",
			"Type constraint `matches(Regex(\"[A-Za-z_][A-Za-z0-9_]*\"))` violated.",
			"cannot start with a digit",
		},
		// A hint that guesses is worse than none: it trains people to ignore
		// the ones that are right.
		{"unrecognized", "Something else went wrong entirely.", ""},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			e := &EvalError{File: "env.pkl", Err: errors.New(tc.msg)}
			got := e.Hint()
			if tc.want == "" {
				if got != "" {
					t.Errorf("expected no hint, got %q", got)
				}
				return
			}
			if !strings.Contains(got, tc.want) {
				t.Errorf("hint %q should mention %q", got, tc.want)
			}
		})
	}
}
