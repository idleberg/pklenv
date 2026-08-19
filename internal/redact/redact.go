// Package redact implements pklenv's output masking.
//
// Masking is opt-in and explicit: a value is only ever masked because a
// `redactions` glob matched its variable name or because a `redact` flag said
// so. Nothing is inferred from where a value came from.
//
// This is output-time text scanning, not access control. A masked value is
// still injected into the child process verbatim, and a child that writes it
// somewhere pklenv cannot see (a file, a network call) is outside this
// package's reach.
package redact

import (
	"bytes"
	"io"
	"path"
	"sort"
	"strings"
	"sync"
)

// Placeholder replaces a masked value in any output pklenv produces.
const Placeholder = "[redacted]"

// minMaskLength is the shortest value worth masking. Masking a one- or
// two-character value would replace so much unrelated text that the output
// becomes unreadable, and such a value has no meaningful secrecy anyway.
const minMaskLength = 4

// Decision is the redaction state of a single variable.
type Decision int

const (
	// Undeclared means no rule covers this variable. It is not masked, and it
	// is eligible for the "this looks sensitive" warning.
	Undeclared Decision = iota
	// Redacted means the value is masked in output.
	Redacted
	// Waived means an explicit `redact = false` opted the variable out. It is
	// not masked, and the explicit decision suppresses the warning.
	Waived
)

// Decide resolves the redaction state of one variable.
//
// An explicit per-variable flag always wins over the globs — that is the whole
// point of the flag, in both directions: `true` covers a value the globs miss,
// `false` waives one they match too eagerly.
//
// Globs are matched case-sensitively. They are written by hand against names
// the author controls, and environment variable names are case-sensitive on
// POSIX, so quietly widening them would be the surprising behaviour.
func Decide(name string, redact *bool, globs []string) Decision {
	if redact != nil {
		if *redact {
			return Redacted
		}
		return Waived
	}
	for _, g := range globs {
		// path.Match only errors on a malformed pattern; treat that as a
		// non-match here. Patterns are validated up front by ValidateGlobs so
		// the user hears about it once, clearly, rather than via silence.
		if ok, err := path.Match(g, name); err == nil && ok {
			return Redacted
		}
	}
	return Undeclared
}

// ValidateGlobs reports the first syntactically invalid pattern, so a typo
// surfaces as an error rather than as a silently unmasked secret.
func ValidateGlobs(globs []string) error {
	for _, g := range globs {
		if _, err := path.Match(g, ""); err != nil {
			return &InvalidGlobError{Pattern: g, Err: err}
		}
	}
	return nil
}

// InvalidGlobError reports a malformed redaction pattern.
type InvalidGlobError struct {
	Pattern string
	Err     error
}

func (e *InvalidGlobError) Error() string {
	return "invalid redaction pattern " + e.Pattern + ": " + e.Err.Error()
}

func (e *InvalidGlobError) Unwrap() error { return e.Err }

// Hint returns the action that resolves this failure.
//
// path.Match has exactly one syntax error — an unterminated character class —
// so unlike most diagnostics there is nothing to guess at here.
func (e *InvalidGlobError) Hint() string {
	return "redaction patterns are shell globs: * matches any run of characters, " +
		"? a single one, and [abc] a set that must be closed"
}

// Masker replaces a fixed set of literal values wherever they appear in text.
type Masker struct {
	values []string
}

// New builds a Masker for the given literal values.
//
// Values are masked longest-first so that a secret which contains another
// secret as a substring is replaced whole, rather than being partially
// rewritten into something that leaks its remainder. Values shorter than
// minMaskLength, and empty values, are dropped: masking them would shred
// unrelated output to no benefit.
func New(values []string) *Masker {
	seen := make(map[string]struct{}, len(values))
	kept := make([]string, 0, len(values))
	for _, v := range values {
		if len(v) < minMaskLength {
			continue
		}
		if _, dup := seen[v]; dup {
			continue
		}
		seen[v] = struct{}{}
		kept = append(kept, v)
	}
	sort.Slice(kept, func(i, j int) bool { return len(kept[i]) > len(kept[j]) })
	return &Masker{values: kept}
}

// Empty reports whether the Masker would leave text untouched, letting callers
// skip the interception plumbing entirely.
func (m *Masker) Empty() bool { return m == nil || len(m.values) == 0 }

// Mask returns s with every known value replaced by Placeholder.
func (m *Masker) Mask(s string) string {
	if m.Empty() {
		return s
	}
	for _, v := range m.values {
		s = strings.ReplaceAll(s, v, Placeholder)
	}
	return s
}

// longest reports the length of the longest masked value, which bounds how
// much trailing text a streaming writer must hold back.
func (m *Masker) longest() int {
	if m.Empty() {
		return 0
	}
	return len(m.values[0]) // sorted longest-first by New
}

// maxHold caps the unflushed tail a Writer will accumulate while waiting for a
// newline. Without it, a child process that prints a long prompt without a
// trailing newline would appear to hang.
const maxHold = 8192

// Writer wraps w so that everything written through it is masked.
//
// Masking is applied per line, because a value split across two Write calls
// would otherwise slip through unmatched. Complete lines are flushed
// immediately; an incomplete trailing line is held only until it is completed,
// grows past maxHold, or Close is called — at which point everything except a
// short overlap tail is released, so interactive prompts still appear.
//
// The returned writer is safe for concurrent use, since a child's stdout and
// stderr are typically copied by separate goroutines into the same destination.
func (m *Masker) Writer(w io.Writer) io.WriteCloser {
	if m.Empty() {
		return nopCloser{w}
	}
	return &maskWriter{w: w, m: m}
}

type nopCloser struct{ io.Writer }

func (nopCloser) Close() error { return nil }

type maskWriter struct {
	mu  sync.Mutex
	w   io.Writer
	m   *Masker
	buf bytes.Buffer
}

func (mw *maskWriter) Write(p []byte) (int, error) {
	mw.mu.Lock()
	defer mw.mu.Unlock()

	mw.buf.Write(p)

	// Flush every complete line.
	for {
		i := bytes.IndexByte(mw.buf.Bytes(), '\n')
		if i < 0 {
			break
		}
		line := make([]byte, i+1)
		_, _ = mw.buf.Read(line)
		if err := mw.emit(line); err != nil {
			return 0, err
		}
	}

	// Release the held tail if it has grown unreasonable, keeping back just
	// enough bytes that a value straddling the boundary still matches.
	if overlap := mw.m.longest() - 1; mw.buf.Len() > maxHold {
		release := mw.buf.Len() - overlap
		if release > 0 {
			chunk := make([]byte, release)
			_, _ = mw.buf.Read(chunk)
			if err := mw.emit(chunk); err != nil {
				return 0, err
			}
		}
	}

	// Report the full length: the caller's bytes are all accounted for, whether
	// they went to w or are held in the buffer. Reporting less would make
	// io.Copy treat a deliberate hold-back as a short write.
	return len(p), nil
}

// Close flushes whatever is still held, masked.
func (mw *maskWriter) Close() error {
	mw.mu.Lock()
	defer mw.mu.Unlock()
	if mw.buf.Len() == 0 {
		return nil
	}
	rest := mw.buf.Bytes()
	err := mw.emit(rest)
	mw.buf.Reset()
	return err
}

func (mw *maskWriter) emit(b []byte) error {
	_, err := io.WriteString(mw.w, mw.m.Mask(string(b)))
	return err
}
