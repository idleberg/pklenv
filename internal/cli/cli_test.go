package cli

import (
	"bytes"
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/charmbracelet/lipgloss"
	"github.com/muesli/termenv"

	"github.com/idleberg/pklenv/internal/config"
)

func requirePkl(t *testing.T) {
	t.Helper()
	if _, err := exec.LookPath("pkl"); err != nil {
		t.Skip("pkl not on PATH; run under `mise exec` or `mise run test`")
	}
}

// schemaPath locates the shipped Pkl schema relative to this package.
func schemaPath(t *testing.T) string {
	t.Helper()
	abs, err := filepath.Abs("../../schema/PklEnv.pk")
	if err != nil {
		t.Fatal(err)
	}
	return abs
}

// writeConfig drops an env config into a temp dir, amending the real schema.
func writeConfig(t *testing.T, dir, name, body string) string {
	t.Helper()
	content := "amends \"" + schemaPath(t) + "\"\n\n" + body
	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

// run executes the CLI with captured output, from within dir.
//
// The CI masking directives carry the literal value by design and are written
// to the unmasked stream, so under a real GitHub Actions runner they land in
// the same buffer the leak assertions scan. Neutralised here rather than in
// each test: no test through this helper is about CI directives, and one that
// is should exercise maskForCI directly.
func run(t *testing.T, dir string, args ...string) (stdout, stderr string, err error) {
	t.Helper()
	t.Setenv("GITHUB_ACTIONS", "")

	prev, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chdir(dir); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chdir(prev) })

	var out, errBuf bytes.Buffer
	io := &IO{Out: &out, Err: &errBuf, rawOut: &out}

	cmd := NewRootCmd(io)
	cmd.SetArgs(args)
	cmd.SetOut(&out)
	cmd.SetErr(&errBuf)
	cmd.SetIn(strings.NewReader(""))

	err = cmd.ExecuteContext(context.Background())
	io.Close()
	return out.String(), errBuf.String(), err
}

const basicConfig = `
redactions { "*_TOKEN" }

vars {
  ["NODE_ENV"] = "production"
  ["API_TOKEN"] = "tok_supersecret_value"
  ["GREETING"] = "hello world"
}
`

func TestEmitWritesDotenv(t *testing.T) {
	requirePkl(t)

	dir := t.TempDir()
	writeConfig(t, dir, "env.pkl", basicConfig)

	if _, stderr, err := run(t, dir, "emit"); err != nil {
		t.Fatalf("emit failed: %v\n%s", err, stderr)
	}

	got, err := os.ReadFile(filepath.Join(dir, ".env"))
	if err != nil {
		t.Fatal(err)
	}
	content := string(got)

	for _, want := range []string{
		"NODE_ENV=production",
		`GREETING="hello world"`,
		"API_TOKEN=tok_supersecret_value",
	} {
		if !strings.Contains(content, want) {
			t.Errorf("missing %q in:\n%s", want, content)
		}
	}
}

// The written file may hold secrets; 0644 would make them world-readable.
func TestEmitWritesRestrictivePermissions(t *testing.T) {
	requirePkl(t)

	dir := t.TempDir()
	writeConfig(t, dir, "env.pkl", basicConfig)
	if _, _, err := run(t, dir, "emit"); err != nil {
		t.Fatal(err)
	}

	info, err := os.Stat(filepath.Join(dir, ".env"))
	if err != nil {
		t.Fatal(err)
	}
	if perm := info.Mode().Perm(); perm != 0o600 {
		t.Errorf("permissions = %o, want 600", perm)
	}
}

// Redaction applies to pklenv's own output. The value is written to the file
// verbatim — masking is about logs, not about the artifact.
func TestEmitMasksItsOwnOutput(t *testing.T) {
	requirePkl(t)

	dir := t.TempDir()
	writeConfig(t, dir, "env.pkl", basicConfig+`
// force the value into a log line
`)
	stdout, stderr, err := run(t, dir, "emit", "--verbose")
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(stdout+stderr, "tok_supersecret_value") {
		t.Errorf("redacted value leaked into output:\n%s%s", stdout, stderr)
	}
}

func TestEmitDiscoversEveryConfig(t *testing.T) {
	requirePkl(t)

	dir := t.TempDir()
	writeConfig(t, dir, "env.pkl", basicConfig)
	writeConfig(t, dir, "env.staging.pkl", `vars { ["TIER"] = "staging" }`)

	if _, stderr, err := run(t, dir, "emit"); err != nil {
		t.Fatalf("emit failed: %v\n%s", err, stderr)
	}

	for _, name := range []string{".env", ".env.staging"} {
		if _, err := os.Stat(filepath.Join(dir, name)); err != nil {
			t.Errorf("expected %s to be written: %v", name, err)
		}
	}
}

func TestEmitSingleFileRestrictsToThatFile(t *testing.T) {
	requirePkl(t)

	dir := t.TempDir()
	writeConfig(t, dir, "env.pkl", basicConfig)
	writeConfig(t, dir, "env.staging.pkl", `vars { ["TIER"] = "staging" }`)

	if _, stderr, err := run(t, dir, "emit", "env.staging.pkl"); err != nil {
		t.Fatalf("emit failed: %v\n%s", err, stderr)
	}

	if _, err := os.Stat(filepath.Join(dir, ".env.staging")); err != nil {
		t.Errorf("expected .env.staging: %v", err)
	}
	if _, err := os.Stat(filepath.Join(dir, ".env")); err == nil {
		t.Error("naming one file must not trigger the discovery sweep")
	}
}

// Without a terminal there is nobody to answer the prompt, and neither default
// is safe: yes destroys a file silently, no looks like a bug.
func TestEmitRefusesOverwriteWithoutTTY(t *testing.T) {
	requirePkl(t)

	dir := t.TempDir()
	writeConfig(t, dir, "env.pkl", basicConfig)
	if err := os.WriteFile(filepath.Join(dir, ".env"), []byte("EXISTING=1\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	_, _, err := run(t, dir, "emit")
	if err == nil {
		t.Fatal("expected a refusal to overwrite without a TTY")
	}
	var hinted hinter
	if !errors.As(err, &hinted) || !strings.Contains(hinted.Hint(), "--force") {
		t.Errorf("the hint should name --force: %v", err)
	}

	got, _ := os.ReadFile(filepath.Join(dir, ".env"))
	if string(got) != "EXISTING=1\n" {
		t.Error("the existing file must be left untouched")
	}
}

// A picker with nowhere to draw does not fail loudly on its own: it renders
// into a pipe and waits, which in CI is indistinguishable from a hang.
func TestEmitInteractiveRefusesWithoutTTY(t *testing.T) {
	requirePkl(t)

	dir := t.TempDir()
	writeConfig(t, dir, "env.pkl", basicConfig)

	_, _, err := run(t, dir, "emit", "--interactive")
	if err == nil {
		t.Fatal("expected --interactive to refuse without a TTY")
	}
	var hinted hinter
	if !errors.As(err, &hinted) || !strings.Contains(hinted.Hint(), "--interactive") {
		t.Errorf("the hint should say how to proceed without it: %v", err)
	}
	if _, err := os.Stat(filepath.Join(dir, ".env")); err == nil {
		t.Error("a refused picker must not write anything")
	}
}

// The two ways of choosing a config contradict each other, and silently letting
// one win would make the other look broken.
func TestEmitInteractiveRejectsExplicitFile(t *testing.T) {
	dir := t.TempDir()
	writeConfig(t, dir, "env.pkl", basicConfig)

	_, _, err := run(t, dir, "emit", "--interactive", "env.pkl")
	if err == nil || !strings.Contains(err.Error(), "--interactive") {
		t.Fatalf("expected --interactive with a FILE to be rejected, got %v", err)
	}
}

func TestEmitForceOverwrites(t *testing.T) {
	requirePkl(t)

	dir := t.TempDir()
	writeConfig(t, dir, "env.pkl", basicConfig)
	if err := os.WriteFile(filepath.Join(dir, ".env"), []byte("EXISTING=1\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	if _, stderr, err := run(t, dir, "emit", "--force"); err != nil {
		t.Fatalf("emit --force failed: %v\n%s", err, stderr)
	}

	got, _ := os.ReadFile(filepath.Join(dir, ".env"))
	if strings.Contains(string(got), "EXISTING") {
		t.Error("--force should have replaced the file")
	}
}

func TestEmitWarnsAboutUnredactedSensitiveName(t *testing.T) {
	requirePkl(t)

	dir := t.TempDir()
	writeConfig(t, dir, "env.pkl", `
vars {
  ["DB_PASSWORD"] = "hunter2000"
  ["NODE_ENV"] = "production"
}
`)
	_, stderr, err := run(t, dir, "emit")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(stderr, "DB_PASSWORD") {
		t.Errorf("expected a warning naming DB_PASSWORD, got:\n%s", stderr)
	}
	// Names only. Printing the value is the hazard being warned about.
	if strings.Contains(stderr, "hunter2000") {
		t.Errorf("the warning must never print the value:\n%s", stderr)
	}
}

// An explicit redact = false records that somebody looked, and silences it.
func TestEmitWaiverSilencesWarning(t *testing.T) {
	requirePkl(t)

	dir := t.TempDir()
	writeConfig(t, dir, "env.pkl", `
vars {
  ["DB_PASSWORD"] = new Var { value = "not-a-secret"; redact = false }
}
`)
	_, stderr, err := run(t, dir, "emit")
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(stderr, "looks sensitive") {
		t.Errorf("an explicit waiver should silence the warning, got:\n%s", stderr)
	}
}

// A covering glob means the variable is handled; there is nothing to warn about.
func TestEmitRedactionSilencesWarning(t *testing.T) {
	requirePkl(t)

	dir := t.TempDir()
	writeConfig(t, dir, "env.pkl", `
redactions { "*_PASSWORD" }

vars {
  ["DB_PASSWORD"] = "hunter2000"
}
`)
	_, stderr, err := run(t, dir, "emit")
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(stderr, "looks sensitive") {
		t.Errorf("a covering glob should silence the warning, got:\n%s", stderr)
	}
}

func TestStrictPromotesWarningToError(t *testing.T) {
	requirePkl(t)

	dir := t.TempDir()
	writeConfig(t, dir, "env.pkl", `vars { ["DB_PASSWORD"] = "hunter2000" }`)

	_, _, err := run(t, dir, "emit", "--strict")
	if err == nil {
		t.Fatal("expected --strict to turn the warning into an error")
	}
	if _, statErr := os.Stat(filepath.Join(dir, ".env")); statErr == nil {
		t.Error("--strict should fail before writing anything")
	}
}

// PKLENV_STRICT is how a CI job asks for --strict once instead of on every
// command, so it has to reach a run that names no flag at all.
func TestStrictDefaultsFromEnv(t *testing.T) {
	requirePkl(t)

	dir := t.TempDir()
	writeConfig(t, dir, "env.pkl", `vars { ["DB_PASSWORD"] = "hunter2000" }`)

	t.Setenv(strictEnv, "1")

	_, _, err := run(t, dir, "emit")
	if err == nil {
		t.Fatal("expected PKLENV_STRICT to turn the warning into an error")
	}
	if !strings.Contains(err.Error(), strictEnv) {
		t.Errorf("the failure should name what asked for it, got: %v", err)
	}
	if _, statErr := os.Stat(filepath.Join(dir, ".env")); statErr == nil {
		t.Error("strict should fail before writing anything")
	}
}

// The flag stays the last word, so one command can opt out of an environment
// that turned strictness on for the job.
func TestStrictEnvOverriddenByFlag(t *testing.T) {
	requirePkl(t)

	dir := t.TempDir()
	writeConfig(t, dir, "env.pkl", `vars { ["DB_PASSWORD"] = "hunter2000" }`)

	t.Setenv(strictEnv, "1")

	if _, stderr, err := run(t, dir, "emit", "--strict=false"); err != nil {
		t.Fatalf("--strict=false should override the environment: %v\n%s", err, stderr)
	}
	if _, statErr := os.Stat(filepath.Join(dir, ".env")); statErr != nil {
		t.Error("the file should have been written")
	}
}

// An unset or explicitly false variable leaves the warning advisory.
func TestStrictEnvFalseValues(t *testing.T) {
	requirePkl(t)

	for _, v := range []string{"", "0", "false", "off", "no"} {
		t.Run("value="+v, func(t *testing.T) {
			dir := t.TempDir()
			writeConfig(t, dir, "env.pkl", `vars { ["DB_PASSWORD"] = "hunter2000" }`)

			t.Setenv(strictEnv, v)

			if _, stderr, err := run(t, dir, "emit"); err != nil {
				t.Fatalf("%s=%q should not be strict: %v\n%s", strictEnv, v, err, stderr)
			}
		})
	}
}

// A value pklenv does not recognize stays truthy — a variable that exists to
// tighten a check must not loosen it on a typo — but silence there is what makes
// the typo invisible, so the run says what it saw and carries on being strict.
func TestStrictEnvUnrecognizedWarnsAndStaysOn(t *testing.T) {
	requirePkl(t)

	dir := t.TempDir()
	writeConfig(t, dir, "env.pkl", `vars { ["DB_PASSWORD"] = "hunter2000" }`)

	t.Setenv(strictEnv, "ture")

	_, stderr, err := run(t, dir, "emit")
	if err == nil {
		t.Fatal("an unrecognized value must not quietly turn strictness off")
	}
	if !strings.Contains(stderr, "ture") {
		t.Errorf("the warning should name the value it did not recognize, got:\n%s", stderr)
	}
	if !strings.Contains(stderr, strictEnv) {
		t.Errorf("the warning should name the variable, got:\n%s", stderr)
	}
}

// A recognized value is not remarked on, or the warning becomes noise every CI
// job prints.
func TestStrictEnvRecognizedValuesAreSilent(t *testing.T) {
	requirePkl(t)

	for _, v := range []string{"1", "true", "yes", "on"} {
		t.Run("value="+v, func(t *testing.T) {
			dir := t.TempDir()
			writeConfig(t, dir, "env.pkl", `vars { ["NODE_ENV"] = "production" }`)

			t.Setenv(strictEnv, v)

			if _, stderr, err := run(t, dir, "emit"); err != nil {
				t.Fatalf("emit failed: %v\n%s", err, stderr)
			} else if strings.Contains(stderr, "unrecognized") {
				t.Errorf("%s=%q should not warn, got:\n%s", strictEnv, v, stderr)
			}
		})
	}
}

// Discovery treats files as independent, so a broken config must not take the
// valid ones down with it — including the ones that sort after it.
func TestEmitContinuesPastABrokenConfig(t *testing.T) {
	requirePkl(t)

	dir := t.TempDir()
	writeConfig(t, dir, "env.pkl", basicConfig)
	writeConfig(t, dir, "env.broken.pkl", `vars { ["OK"] = read("env:PKLENV_DEFINITELY_UNSET") }`)
	writeConfig(t, dir, "env.staging.pkl", `vars { ["TIER"] = "staging" }`)

	_, stderr, err := run(t, dir, "emit")
	if err == nil {
		t.Fatal("expected a non-zero result when a config failed")
	}
	if !strings.Contains(err.Error(), "1 of 3") {
		t.Errorf("the summary should count the failures, got: %v", err)
	}
	if !strings.Contains(stderr, "env.broken.pkl") {
		t.Errorf("the failing config should be named, got:\n%s", stderr)
	}

	// env.broken.pkl sorts ahead of both of these.
	for _, name := range []string{".env", ".env.staging"} {
		if _, statErr := os.Stat(filepath.Join(dir, name)); statErr != nil {
			t.Errorf("expected %s to be written despite the earlier failure: %v", name, statErr)
		}
	}
	if _, statErr := os.Stat(filepath.Join(dir, ".env.broken")); statErr == nil {
		t.Error("the broken config must not produce a file")
	}
}

func TestRunInjectsVariables(t *testing.T) {
	requirePkl(t)

	dir := t.TempDir()
	writeConfig(t, dir, "env.pkl", basicConfig)

	stdout, stderr, err := run(t, dir, "run", "--", "sh", "-c", "echo NODE_ENV=$NODE_ENV")
	if err != nil {
		t.Fatalf("run failed: %v\n%s", err, stderr)
	}
	if !strings.Contains(stdout, "NODE_ENV=production") {
		t.Errorf("expected the injected value, got: %q", stdout)
	}
}

// The reason run pipes the child's streams at all.
func TestRunMasksChildOutput(t *testing.T) {
	requirePkl(t)

	dir := t.TempDir()
	writeConfig(t, dir, "env.pkl", basicConfig)

	stdout, _, err := run(t, dir, "run", "--", "sh", "-c", "echo token=$API_TOKEN")
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(stdout, "tok_supersecret_value") {
		t.Errorf("the child leaked a redacted value: %q", stdout)
	}
	if !strings.Contains(stdout, "[redacted]") {
		t.Errorf("expected a placeholder, got: %q", stdout)
	}
}

// --raw trades the guarantee for a faithful terminal, and must say so.
func TestRunRawSkipsChildMasking(t *testing.T) {
	requirePkl(t)

	dir := t.TempDir()
	writeConfig(t, dir, "env.pkl", basicConfig)

	_, stderr, err := run(t, dir, "run", "--raw", "--", "true")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(stderr, "not masked") {
		t.Errorf("--raw must warn that masking is off, got:\n%s", stderr)
	}
}

func TestRunPropagatesExitCode(t *testing.T) {
	requirePkl(t)

	dir := t.TempDir()
	writeConfig(t, dir, "env.pkl", basicConfig)

	_, _, err := run(t, dir, "run", "--", "sh", "-c", "exit 42")
	if err == nil {
		t.Fatal("expected a non-zero exit to surface as an error")
	}
	var exitErr *ExitError
	if !asExit(err, &exitErr) {
		t.Fatalf("expected an ExitError, got %T: %v", err, err)
	}
	if exitErr.Code != 42 {
		t.Errorf("exit code = %d, want 42", exitErr.Code)
	}
}

func asExit(err error, target **ExitError) bool {
	e, ok := err.(*ExitError)
	if ok {
		*target = e
	}
	return ok
}

// The config is the source of truth; an ambient value must not win.
func TestRunConfigOverridesAmbientEnv(t *testing.T) {
	requirePkl(t)

	dir := t.TempDir()
	writeConfig(t, dir, "env.pkl", basicConfig)
	t.Setenv("NODE_ENV", "development")

	stdout, _, err := run(t, dir, "run", "--", "sh", "-c", "echo NODE_ENV=$NODE_ENV")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(stdout, "NODE_ENV=production") {
		t.Errorf("the config should win over the ambient value, got: %q", stdout)
	}
}

// Ambient variables the config says nothing about are passed through.
func TestRunPreservesAmbientEnv(t *testing.T) {
	requirePkl(t)

	dir := t.TempDir()
	writeConfig(t, dir, "env.pkl", basicConfig)
	t.Setenv("PKLENV_AMBIENT_MARKER", "still-here")

	stdout, _, err := run(t, dir, "run", "--", "sh", "-c", "echo M=$PKLENV_AMBIENT_MARKER")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(stdout, "M=still-here") {
		t.Errorf("ambient variables should survive, got: %q", stdout)
	}
}

func TestEmitReportsMissingConfig(t *testing.T) {
	dir := t.TempDir()

	_, _, err := run(t, dir, "emit")
	if err == nil {
		t.Fatal("expected an error when no config exists")
	}
	if !strings.Contains(err.Error(), "no env*.pkl") {
		t.Errorf("error should say what was looked for: %v", err)
	}
}

// The command goes after --, which Cobra's "requires at least 1 arg(s)" says
// nothing about.
func TestRunWithoutACommand(t *testing.T) {
	dir := t.TempDir()
	writeConfig(t, dir, "env.pkl", basicConfig)

	_, _, err := run(t, dir, "run")
	if err == nil {
		t.Fatal("expected an error when no command was given")
	}
	var hinted hinter
	if !errors.As(err, &hinted) {
		t.Fatalf("the error should carry a hint: %v", err)
	}
	if !strings.Contains(hinted.Hint(), "pklenv run --") {
		t.Errorf("the hint should show the form: %v", hinted.Hint())
	}
}

// Log fields must arrive unstyled. Styling them ourselves and handing them to
// charm log gets them quoted as data containing control characters, which is
// how var="\x1b[1mDB_PASSWORD\x1b[0m" happened.
//
// The color profile is forced, because otherwise a buffer-backed test looks
// like a pipe, every style renders to nothing, and the bug is invisible.
func TestLogFieldsCarryNoEscapeSequences(t *testing.T) {
	requirePkl(t)

	prev := lipgloss.ColorProfile()
	lipgloss.SetColorProfile(termenv.ANSI)
	t.Cleanup(func() { lipgloss.SetColorProfile(prev) })

	dir := t.TempDir()
	writeConfig(t, dir, "env.pkl", "vars {\n  [\"DB_PASSWORD\"] = \"hunter2\"\n}\n")

	_, stderr, err := run(t, dir, "emit", "--outdir", dir)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(stderr, "DB_PASSWORD") {
		t.Fatalf("expected the name in the message, got %q", stderr)
	}
	if strings.Contains(stderr, "\x1b[") {
		t.Fatalf("escape sequences reached a non-terminal stream: %q", stderr)
	}
}

// Without a terminal, a Pkl diagnostic is summarized: it quotes source, and
// source can quote values that were never classified as secret because the
// evaluation that would have classified them failed.
func TestReportFatalSummarizesPklErrors(t *testing.T) {
	var errBuf bytes.Buffer
	stdio := &IO{Out: &bytes.Buffer{}, Err: &errBuf}

	reportFatal(stdio, &config.EvalError{
		File: "env.pkl",
		Err:  errors.New("–– Pkl Error ––\nType constraint violated.\nValue: \"tok_supersecret\"\n\n6 | x = 1"),
	})

	got := errBuf.String()
	if strings.Contains(got, "tok_supersecret") {
		t.Fatalf("the value reached a non-terminal stream: %q", got)
	}
	if !strings.Contains(got, "Type constraint violated.") {
		t.Errorf("the classification should survive: %q", got)
	}
	if !strings.Contains(got, "--verbose") {
		t.Errorf("should point at the way to see more: %q", got)
	}
}

// --verbose is the opt-in, and it opts all the way in.
func TestReportFatalVerboseKeepsDetail(t *testing.T) {
	var errBuf bytes.Buffer
	stdio := &IO{Out: &bytes.Buffer{}, Err: &errBuf, Verbose: true}

	reportFatal(stdio, &config.EvalError{
		File: "env.pkl",
		Err:  errors.New("Type constraint violated.\nValue: \"tok_supersecret\""),
	})

	if !strings.Contains(errBuf.String(), "tok_supersecret") {
		t.Errorf("verbose should print the full diagnostic: %q", errBuf.String())
	}
}

// Only Pkl's diagnostics are summarized. pklenv's own errors are short and
// value-free, and already carry their own hints.
func TestReportFatalLeavesOwnErrorsAlone(t *testing.T) {
	var errBuf bytes.Buffer
	stdio := &IO{Out: &bytes.Buffer{}, Err: &errBuf}

	reportFatal(stdio, errors.New("no env*.pkl config found in this directory"))

	got := errBuf.String()
	if !strings.Contains(got, "no env*.pkl config found") {
		t.Errorf("own errors print in full: %q", got)
	}
	if strings.Contains(got, "--verbose") {
		t.Errorf("no verbose hint for errors that have no hidden detail: %q", got)
	}
}

// A hint is only useful if it survives the trip up through Cobra and gets
// printed under the error rather than swallowed.
func TestReportFatalPrintsHints(t *testing.T) {
	var errBuf bytes.Buffer
	stdio := &IO{Out: &bytes.Buffer{}, Err: &errBuf}

	reportFatal(stdio, withHint(errors.New("something went wrong"), "try turning it off and on again"))

	got := errBuf.String()
	if !strings.Contains(got, "something went wrong") {
		t.Errorf("the error should print: %q", got)
	}
	if !strings.Contains(got, "try turning it off and on again") {
		t.Errorf("the hint should print under it: %q", got)
	}
}

// Pkl says "Cannot find resource" for a variable that is not set. That is
// accurate but not actionable on its own.
func TestUnsetVariableGetsAHint(t *testing.T) {
	requirePkl(t)

	dir := t.TempDir()
	writeConfig(t, dir, "env.pkl", `vars { ["X"] = read("env:PKLENV_NOT_SET_ANYWHERE") }`)

	_, _, err := run(t, dir, "emit")
	if err == nil {
		t.Fatal("expected an error")
	}

	var evalErr *config.EvalError
	if !errors.As(err, &evalErr) {
		t.Fatalf("expected an EvalError, got %T", err)
	}
	if !strings.Contains(evalErr.Hint(), "read?") {
		t.Errorf("the hint should point at read?: %q", evalErr.Hint())
	}
}
