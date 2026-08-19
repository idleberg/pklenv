package schema

import (
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/idleberg/pklenv"
)

// config writes a config that amends the vendored schema, which is what asks
// pklenv to maintain it.
func config(t *testing.T, dir string) string {
	t.Helper()
	path := filepath.Join(dir, "env.pkl")
	if err := os.WriteFile(path, []byte("amends \""+Filename+"\"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestWritesWhenReferencedAndNotOtherwise(t *testing.T) {
	dir := t.TempDir()
	cfg := config(t, dir)

	outcome, err := Ensure(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if outcome != Written {
		t.Errorf("outcome = %v, want Written", outcome)
	}
	body, err := os.ReadFile(filepath.Join(dir, Filename))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(body), "open module pklenv.PklEnv") {
		t.Error("the vendored copy should contain the embedded schema")
	}

	// A config that never mentions the schema should not have one dropped next
	// to it: pklenv writing into a directory nobody asked it to is a surprise.
	other := t.TempDir()
	quiet := filepath.Join(other, "env.pkl")
	if err := os.WriteFile(quiet, []byte("vars {}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if outcome, err := Ensure(quiet); err != nil || outcome != Unchanged {
		t.Errorf("outcome = %v, err = %v; want Unchanged and no file", outcome, err)
	}
	if _, err := os.Stat(filepath.Join(other, Filename)); !errors.Is(err, os.ErrNotExist) {
		t.Error("no copy should be written for a config that does not reference it")
	}
}

// TestCurrentCopyIsLeftAlone is the CI case: a committed, matching copy must not
// be rewritten, or every pipeline that checks for a dirty tree starts failing.
func TestCurrentCopyIsLeftAlone(t *testing.T) {
	dir := t.TempDir()
	cfg := config(t, dir)
	if _, err := Ensure(cfg); err != nil {
		t.Fatal(err)
	}

	target := filepath.Join(dir, Filename)
	before, err := os.Stat(target)
	if err != nil {
		t.Fatal(err)
	}

	outcome, err := Ensure(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if outcome != Unchanged {
		t.Errorf("outcome = %v, want Unchanged", outcome)
	}
	after, err := os.Stat(target)
	if err != nil {
		t.Fatal(err)
	}
	if !before.ModTime().Equal(after.ModTime()) {
		t.Error("a current copy must not be rewritten")
	}
}

// TestTamperedCopyIsReplaced is the reason Ensure verifies rather than merely
// creating when absent. The vendored schema is executed on every evaluation, so
// a locally edited copy would run inside the boundary the permission flags draw.
func TestTamperedCopyIsReplaced(t *testing.T) {
	dir := t.TempDir()
	cfg := config(t, dir)
	if _, err := Ensure(cfg); err != nil {
		t.Fatal(err)
	}

	target := filepath.Join(dir, Filename)
	tampered := "// " + marker + "; do not edit.\nbackdoor = read(\"env:AWS_SECRET_ACCESS_KEY\")\n"
	if err := os.WriteFile(target, []byte(tampered), 0o644); err != nil {
		t.Fatal(err)
	}

	outcome, err := Ensure(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if outcome != Refreshed {
		t.Errorf("outcome = %v, want Refreshed", outcome)
	}
	body, err := os.ReadFile(target)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(body), "backdoor") {
		t.Error("a tampered copy must be replaced, not trusted")
	}
	if string(body) != header+pklenv.Schema {
		t.Error("the replacement should be exactly the embedded schema")
	}
}

// TestForeignFileIsNotClobbered guards the other half of automatic rewriting: a
// name collision must not become silent data loss.
func TestForeignFileIsNotClobbered(t *testing.T) {
	dir := t.TempDir()
	cfg := config(t, dir)

	target := filepath.Join(dir, Filename)
	mine := "// something a user wrote themselves\nfoo = 1\n"
	if err := os.WriteFile(target, []byte(mine), 0o600); err != nil {
		t.Fatal(err)
	}

	if _, err := Ensure(cfg); !errors.Is(err, ErrForeign) {
		t.Errorf("err = %v, want ErrForeign", err)
	}
	body, err := os.ReadFile(target)
	if err != nil {
		t.Fatal(err)
	}
	if string(body) != mine {
		t.Error("a file pklenv did not write must be left exactly as it was")
	}
}

// TestReadOnlyDirectory covers the read-only checkout: a stale copy is usable
// and only warrants a warning, while a missing one is fatal and must say why.
func TestReadOnlyDirectory(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("directory permissions do not work this way on Windows")
	}
	if os.Geteuid() == 0 {
		t.Skip("root ignores the write bit")
	}

	t.Run("stale copy is used", func(t *testing.T) {
		dir := t.TempDir()
		cfg := config(t, dir)
		if _, err := Ensure(cfg); err != nil {
			t.Fatal(err)
		}
		stale := "// " + marker + "; do not edit.\n// an older release wrote this\n"
		if err := os.WriteFile(filepath.Join(dir, Filename), []byte(stale), 0o644); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(dir, 0o555); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = os.Chmod(dir, 0o755) })

		outcome, err := Ensure(cfg)
		if err != nil {
			t.Fatalf("a stale copy should not be fatal: %v", err)
		}
		if outcome != Stale {
			t.Errorf("outcome = %v, want Stale", outcome)
		}
	})

	t.Run("missing copy is fatal", func(t *testing.T) {
		dir := t.TempDir()
		cfg := config(t, dir)
		if err := os.Chmod(dir, 0o555); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = os.Chmod(dir, 0o755) })

		if _, err := Ensure(cfg); err == nil {
			t.Error("a missing copy in an unwritable directory must be reported")
		}
	})
}

// TestHeaderCarriesNoVersion keeps the file stable across pklenv releases. A
// version string in the header would rewrite the file on every upgrade even
// when the schema is untouched, filling diffs with changes that mean nothing.
func TestHeaderCarriesNoVersion(t *testing.T) {
	for _, digit := range []string{"0.", "1.", "v0", "v1"} {
		if strings.Contains(header, digit) {
			t.Errorf("the header should carry no version, found %q in %q", digit, header)
		}
	}
}

// TestFilenameEscapesDiscovery pins the naming constraint. config.Discover keeps
// env.pkl and anything prefixed "env."; a schema caught by that glob would be
// treated as a config and emitted to a .env file of its own.
func TestFilenameEscapesDiscovery(t *testing.T) {
	if Filename == "env.pkl" || strings.HasPrefix(Filename, "env.") {
		t.Errorf("%q would be picked up by config.Discover", Filename)
	}
	if !strings.HasSuffix(Filename, ".pkl") {
		t.Errorf("%q should still be a Pkl module", Filename)
	}
}
