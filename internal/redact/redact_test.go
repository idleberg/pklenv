package redact

import (
	"bytes"
	"errors"
	"io"
	"strings"
	"testing"
)

func boolp(b bool) *bool { return &b }

func mustWrite(t *testing.T, w io.Writer, s string) {
	t.Helper()
	if _, err := io.WriteString(w, s); err != nil {
		t.Fatal(err)
	}
}

func mustClose(t *testing.T, c io.Closer) {
	t.Helper()
	if err := c.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestDecide(t *testing.T) {
	globs := []string{"*_TOKEN", "SECRET_*"}

	tests := []struct {
		name   string
		varm   string
		redact *bool
		want   Decision
	}{
		{"glob suffix match", "GITHUB_TOKEN", nil, Redacted},
		{"glob prefix match", "SECRET_SAUCE", nil, Redacted},
		{"no rule", "NODE_ENV", nil, Undeclared},
		{"explicit true beats absent glob", "NODE_ENV", boolp(true), Redacted},
		{"explicit false waives a matching glob", "PUBLIC_TOKEN", boolp(false), Waived},
		{"explicit true alongside matching glob", "API_TOKEN", boolp(true), Redacted},
		{"case-sensitive globs do not match lowercase", "github_token", nil, Undeclared},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := Decide(tt.varm, tt.redact, globs); got != tt.want {
				t.Errorf("Decide(%q) = %v, want %v", tt.varm, got, tt.want)
			}
		})
	}
}

func TestValidateGlobs(t *testing.T) {
	if err := ValidateGlobs([]string{"*_TOKEN", "OK"}); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if err := ValidateGlobs([]string{"[unclosed"}); err == nil {
		t.Fatal("expected an error for a malformed pattern")
	}
}

func TestMask(t *testing.T) {
	m := New([]string{"hunter2000", "swordfish"})

	got := m.Mask("db=hunter2000 other=swordfish")
	want := "db=" + Placeholder + " other=" + Placeholder
	if got != want {
		t.Errorf("Mask() = %q, want %q", got, want)
	}
}

// A short value would replace so much unrelated text that output becomes
// unreadable, so it is deliberately left alone.
func TestMaskIgnoresShortValues(t *testing.T) {
	m := New([]string{"ab", ""})
	if !m.Empty() {
		t.Fatal("expected short and empty values to be dropped")
	}
	if got := m.Mask("ab cd"); got != "ab cd" {
		t.Errorf("Mask() = %q, want it untouched", got)
	}
}

// A secret containing another secret must be replaced whole; masking the inner
// one first would leave the remainder of the outer one exposed.
func TestMaskLongestFirst(t *testing.T) {
	m := New([]string{"secret", "secret-extended-tail"})
	got := m.Mask("value=secret-extended-tail")
	if got != "value="+Placeholder {
		t.Errorf("Mask() = %q, want the whole value replaced", got)
	}
}

func TestWriterMasksCompleteLines(t *testing.T) {
	var buf bytes.Buffer
	w := New([]string{"hunter2000"}).Writer(&buf)

	if _, err := io.WriteString(w, "starting\ntoken=hunter2000\n"); err != nil {
		t.Fatal(err)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}

	want := "starting\ntoken=" + Placeholder + "\n"
	if buf.String() != want {
		t.Errorf("got %q, want %q", buf.String(), want)
	}
}

// The reason the writer buffers at all: a value split across two Write calls
// would slip through if each chunk were masked independently.
func TestWriterMasksValueSplitAcrossWrites(t *testing.T) {
	var buf bytes.Buffer
	w := New([]string{"hunter2000"}).Writer(&buf)

	mustWrite(t, w, "token=hunt")
	mustWrite(t, w, "er2000\n")
	mustClose(t, w)

	if strings.Contains(buf.String(), "hunter2000") {
		t.Errorf("secret leaked across the write boundary: %q", buf.String())
	}
	if !strings.Contains(buf.String(), Placeholder) {
		t.Errorf("expected a placeholder, got %q", buf.String())
	}
}

// Output with no trailing newline must still reach the destination, or a child
// process's final line would be swallowed.
func TestWriterFlushesUnterminatedTailOnClose(t *testing.T) {
	var buf bytes.Buffer
	w := New([]string{"hunter2000"}).Writer(&buf)

	mustWrite(t, w, "no trailing newline here")
	if buf.Len() != 0 {
		t.Errorf("expected the tail to be held until Close, got %q", buf.String())
	}
	mustClose(t, w)

	if buf.String() != "no trailing newline here" {
		t.Errorf("got %q, want the tail flushed", buf.String())
	}
}

// A long newline-free stream (a progress bar, a prompt) must not be held
// forever, or the child would appear to hang.
func TestWriterReleasesOversizedTail(t *testing.T) {
	var buf bytes.Buffer
	w := New([]string{"hunter2000"}).Writer(&buf)

	mustWrite(t, w, strings.Repeat("x", maxHold+100))
	if buf.Len() == 0 {
		t.Fatal("expected an oversized tail to be released before Close")
	}
	mustClose(t, w)

	if got := buf.Len(); got != maxHold+100 {
		t.Errorf("released %d bytes, want all %d", got, maxHold+100)
	}
}

func TestWriterReportsFullWriteLength(t *testing.T) {
	var buf bytes.Buffer
	w := New([]string{"hunter2000"}).Writer(&buf)

	// Held-back bytes must still count as written, or io.Copy reports a short
	// write and aborts the stream.
	n, err := io.WriteString(w, "held back")
	if err != nil {
		t.Fatal(err)
	}
	if n != len("held back") {
		t.Errorf("Write() = %d, want %d", n, len("held back"))
	}
}

func TestWriterPassthroughWhenNothingToMask(t *testing.T) {
	var buf bytes.Buffer
	w := New(nil).Writer(&buf)

	mustWrite(t, w, "unbuffered")
	if buf.String() != "unbuffered" {
		t.Errorf("expected an empty masker to write straight through, got %q", buf.String())
	}
}

// The one syntax error path.Match reports has a knowable fix, so it carries a
// hint rather than leaving the user to guess at glob syntax.
func TestInvalidGlobErrorHint(t *testing.T) {
	err := ValidateGlobs([]string{"*_TOKEN", "["})
	if err == nil {
		t.Fatal("expected an unterminated character class to be rejected")
	}
	var bad *InvalidGlobError
	if !errors.As(err, &bad) {
		t.Fatalf("expected an *InvalidGlobError, got %T", err)
	}
	if bad.Pattern != "[" {
		t.Errorf("the error should name the offending pattern, got %q", bad.Pattern)
	}
	if !strings.Contains(bad.Hint(), "[abc]") {
		t.Errorf("the hint should show the syntax, got %q", bad.Hint())
	}
}
