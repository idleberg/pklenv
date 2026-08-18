package cli

import (
	"regexp"
	"slices"
	"strings"

	"github.com/charmbracelet/lipgloss"
)

// fileRef matches a config or dotenv path.
//
// Two shapes, because they are spelled differently: anything ending in .pkl,
// and a dotenv file, which starts with the dot instead. The character class
// admits `*` and `<>` so the forms that appear in help and error text —
// `env*.pkl`, `env.<environment>.pkl` — are matched whole rather than in
// pieces.
//
// The optional scheme is for Pkl's diagnostics, which locate a module as
// file:///path/to/env.pkl. Without it the match starts at the slashes and
// leaves `file:` behind in the body text, which looks like a truncation.
var fileRef = regexp.MustCompile(`(?:\w+:)?[\w.\-*/<>]*\.pkl\b|\.env(?:\.[\w\-<>]+)?\b`)

// varNameShape matches an identifier that can only be an environment variable.
//
// The underscore is required, and that is the whole trick: an all-caps word
// without one is indistinguishable from ordinary emphasis, and pklenv's own
// prose is full of those — FILE, NAME, COMMAND, ARGS, CI. Names without an
// underscore are still coloured when the config declared them, which is the
// case where nothing has to be guessed.
var varNameShape = regexp.MustCompile(`\b[A-Z][A-Z0-9]*(?:_[A-Z0-9]+)+\b`)

// defaultRefs is what decorate matches on before a config has been loaded.
var defaultRefs = regexp.MustCompile(fileRef.String() + `|` + varNameShape.String())

// learn teaches the decorator this run's vocabulary.
//
// Declared names remove the guesswork for the ones the shape rule cannot reach
// — PORT, DEBUG, TIER. Secrets are the opposite: they are what must not be
// touched, for the reason given on skipSecret.
func (stdio *IO) learn(names, secrets []string) {
	stdio.secrets = secrets

	// Longest first. Alternation in Go's regexp takes the branch that matches
	// earliest in the pattern rather than the longest match, so with DB before
	// DB_PASSWORD the shorter name would win and colour half the longer one.
	sorted := slices.Clone(names)
	slices.SortFunc(sorted, func(a, b string) int { return len(b) - len(a) })

	parts := make([]string, 0, len(sorted)+2)
	// Paths first, so a dotted filename is claimed whole before any rule that
	// might match a fragment of it.
	parts = append(parts, fileRef.String())
	for _, n := range sorted {
		parts = append(parts, `\b`+regexp.QuoteMeta(n)+`\b`)
	}
	parts = append(parts, varNameShape.String())

	// Compile rather than MustCompile: names are validated before they get
	// here and QuoteMeta makes them literal regardless, but a panic in the
	// output layer would take down a run that had otherwise succeeded. The
	// fallback costs some colour and nothing else.
	if re, err := regexp.Compile(strings.Join(parts, "|")); err == nil {
		stdio.refs = re
	}
}

// skipSecret reports whether colouring this match would break redaction.
//
// Redaction is a byte-level search for the literal value on its way out. A
// colour inserted inside one splits it, the masker no longer finds it, and the
// value is printed in full — a decoration silently disabling the guarantee it
// was drawn on top of. pklenv does not knowingly print values, so this should
// never fire; it exists because there is no sign when it does.
func (stdio *IO) skipSecret(match string) bool {
	for _, s := range stdio.secrets {
		if s != "" && strings.Contains(s, match) {
			return true
		}
	}
	return false
}

// decorate colours the variable names and file paths inside a message.
//
// Only the matches are coloured, never the line: the point is to pick the nouns
// out of the sentence, and a fully coloured line says something else entirely —
// that the line as a whole carries a severity.
//
// base is the style the surrounding text already has, and every segment is
// rendered through it, in one pass. Styles do not nest: the reset that ends a
// coloured match also ends an enclosing faint, so a hint decorated in two
// passes fades back in halfway through and stays bright to the end of the line.
func (stdio *IO) decorate(base lipgloss.Style, msg string) string {
	if msg == "" {
		return msg
	}

	re := stdio.refs
	if re == nil {
		re = defaultRefs
	}
	matches := re.FindAllStringIndex(msg, -1)
	if matches == nil {
		return base.Render(msg)
	}

	st := stdio.styles()
	var b strings.Builder
	last := 0
	for _, loc := range matches {
		m := msg[loc[0]:loc[1]]
		b.WriteString(base.Render(msg[last:loc[0]]))

		switch {
		case stdio.skipSecret(m):
			b.WriteString(base.Render(m))
		case strings.Contains(m, "."):
			// The only matches carrying a dot are paths: an environment
			// variable name cannot contain one and still round-trip a .env file.
			b.WriteString(base.Inherit(st.file).Render(m))
		default:
			b.WriteString(base.Inherit(st.name).Render(m))
		}
		last = loc[1]
	}
	b.WriteString(base.Render(msg[last:]))
	return b.String()
}
