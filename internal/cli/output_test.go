package cli

import (
	"bytes"
	"strings"
	"testing"

	"github.com/idleberg/pklenv/internal/redact"
)

// The directive has to carry the literal value: that is what registers it with
// the runner, and it is why maskForCI writes to the unmasked stream. Asserted
// here because the CLI tests neutralise GITHUB_ACTIONS to keep their leak
// assertions honest.
func TestMaskForCIEmitsDirectivesUnderGitHub(t *testing.T) {
	t.Setenv("GITHUB_ACTIONS", "true")

	var raw, masked bytes.Buffer
	stdio := &IO{Out: &masked, Err: &masked, rawOut: &raw, rawErr: &raw}
	stdio.maskForCI([]string{"tok_supersecret_value", "", "second"})

	got := raw.String()
	for _, want := range []string{
		"::add-mask::tok_supersecret_value\n",
		"::add-mask::second\n",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("missing %q in:\n%s", want, got)
		}
	}
	// An empty value would register a mask matching everything.
	if strings.Contains(got, "::add-mask::\n") {
		t.Errorf("empty value emitted a directive:\n%s", got)
	}
	if masked.Len() != 0 {
		t.Errorf("directives must bypass the masker, got: %q", masked.String())
	}
}

func TestMaskForCISilentOutsideGitHub(t *testing.T) {
	t.Setenv("GITHUB_ACTIONS", "")

	var raw bytes.Buffer
	stdio := &IO{Out: &raw, Err: &raw, rawOut: &raw, rawErr: &raw}
	stdio.maskForCI([]string{"tok_supersecret_value"})

	if raw.Len() != 0 {
		t.Errorf("expected no output off CI, got: %q", raw.String())
	}
}

// Redact wraps both streams and Close flushes what the masker held back; the
// value must not survive either half.
func TestRedactMasksBothStreams(t *testing.T) {
	var out, errBuf bytes.Buffer
	stdio := &IO{Out: &out, Err: &errBuf}

	m := redact.New([]string{"tok_supersecret_value"})
	restore := stdio.Redact(m)
	_, _ = stdio.Out.Write([]byte("stdout tok_supersecret_value\n"))
	_, _ = stdio.Err.Write([]byte("stderr tok_supersecret_value\n"))
	restore()

	if got := out.String() + errBuf.String(); strings.Contains(got, "tok_supersecret_value") {
		t.Errorf("value survived masking:\n%s", got)
	}
	if stdio.Out != &out || stdio.Err != &errBuf {
		t.Error("restore must put the original streams back")
	}
}
