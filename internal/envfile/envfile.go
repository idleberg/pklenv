// Package envfile renders resolved variables as a dotenv-format file.
package envfile

import (
	"fmt"
	"strings"
)

// Render writes the variables as KEY=VALUE lines, in the order given.
//
// Values are quoted only when they need to be. A file full of unnecessary
// quotes is harder to read and to diff, and the common case — a short
// alphanumeric value — needs none.
func Render(names []string, value func(string) string, header string) string {
	var b strings.Builder
	if header != "" {
		for _, line := range strings.Split(strings.TrimRight(header, "\n"), "\n") {
			b.WriteString("# ")
			b.WriteString(line)
			b.WriteString("\n")
		}
		b.WriteString("\n")
	}
	for _, name := range names {
		b.WriteString(name)
		b.WriteString("=")
		b.WriteString(Quote(value(name)))
		b.WriteString("\n")
	}
	return b.String()
}

// Quote renders a value for a dotenv file, quoting and escaping if needed.
//
// Double quotes rather than single, because a value containing a literal
// single quote cannot be escaped inside single quotes in most dotenv parsers,
// whereas backslash escaping inside double quotes is widely understood.
func Quote(v string) string {
	if v == "" {
		return `""`
	}
	if !needsQuoting(v) {
		return v
	}

	var b strings.Builder
	b.WriteByte('"')
	for _, r := range v {
		switch r {
		case '"', '\\', '$', '`':
			b.WriteByte('\\')
			b.WriteRune(r)
		case '\n':
			b.WriteString(`\n`)
		case '\r':
			b.WriteString(`\r`)
		case '\t':
			b.WriteString(`\t`)
		default:
			b.WriteRune(r)
		}
	}
	b.WriteByte('"')
	return b.String()
}

func needsQuoting(v string) bool {
	for _, r := range v {
		switch {
		case r >= 'a' && r <= 'z',
			r >= 'A' && r <= 'Z',
			r >= '0' && r <= '9':
			continue
		}
		switch r {
		case '_', '-', '.', '/', ':', '@', '+', ',':
			continue
		}
		return true
	}
	return false
}

// ValidateName rejects names a shell or dotenv parser could not round-trip.
//
// The Pkl schema already constrains the key type, so a config written against
// it fails earlier and with a better message. This stays as defense in depth:
// configs can reach the CLI without going through that schema.
//
// One of three copies of the same rule — the others are `EnvName` in
// schema/PklEnv.pk, which is the authority, and config.EvalError.Hint, which
// matches on that pattern's text. Keep them in step.
func ValidateName(name string) error {
	if name == "" {
		return fmt.Errorf("empty variable name")
	}
	for i, r := range name {
		switch {
		case r == '_',
			r >= 'a' && r <= 'z',
			r >= 'A' && r <= 'Z':
			continue
		case r >= '0' && r <= '9' && i > 0:
			continue
		}
		return fmt.Errorf("invalid variable name %q: expected letters, digits and underscores, not starting with a digit", name)
	}
	return nil
}
