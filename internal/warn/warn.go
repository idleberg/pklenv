// Package warn implements the "this name looks sensitive but nothing redacts
// it" advisory.
//
// Explicit-only redaction has exactly one failure mode: forgetting. It is
// silent, and the thing you forgot to declare is by definition the thing you
// cared about. This package is the counterweight.
//
// It is advisory and stays advisory. It never changes what resolves, what is
// masked, or what is written — it only prints. The tool's behaviour remains
// fully explicit; a heuristic in the enforcement path would make pklenv's
// guarantees shift between versions as the pattern list grows.
package warn

import (
	"sort"
	"strings"

	"github.com/idleberg/pklenv/internal/redact"
)

// DefaultPatterns are the substrings that mark a variable name as
// sensitive-looking. They are matched case-insensitively.
//
// Deliberately conservative, and deliberately not a bare "KEY": SORT_KEY,
// PUBLIC_KEY, CACHE_KEY_PREFIX and KEYBOARD_SHORTCUTS would all trip it, and a
// warning everyone learns to scroll past is worse than no warning at all —
// it takes the one that mattered down with it.
var DefaultPatterns = []string{
	"SECRET",
	"PASSWORD",
	"PASSWD",
	"TOKEN",
	"CREDENTIAL",
	"PRIVATE_KEY",
	"API_KEY",
}

// Finding names a variable that looks sensitive but carries no redaction rule.
//
// It holds the name only. The value is deliberately absent: printing it is the
// exact hazard being warned about.
type Finding struct {
	Name    string
	Pattern string
}

// Scan reports variables that match a sensitive-looking pattern and are covered
// by no redaction rule.
//
// Only redact.Undeclared is reported. A variable that is already redacted is
// handled, and one explicitly waived with `redact = false` records that
// somebody looked — in both cases there is nothing to say.
//
// Pass nil patterns to use DefaultPatterns.
func Scan(decisions map[string]redact.Decision, patterns []string) []Finding {
	if patterns == nil {
		patterns = DefaultPatterns
	}

	var findings []Finding
	for name, d := range decisions {
		if d != redact.Undeclared {
			continue
		}
		if p, ok := match(name, patterns); ok {
			findings = append(findings, Finding{Name: name, Pattern: p})
		}
	}

	// Stable order: warnings are diffed across CI runs and read by humans.
	sort.Slice(findings, func(i, j int) bool { return findings[i].Name < findings[j].Name })
	return findings
}

// match reports the first pattern contained in name, case-insensitively.
//
// Substring rather than glob: these are fuzzy hints about human naming habits,
// not rules the user wrote, so DATABASE_PASSWORD_FILE should trip on PASSWORD
// the same way PASSWORD does. Case-insensitive for the same reason — unlike the
// user's own redaction globs, nobody chose this list's spelling.
func match(name string, patterns []string) (string, bool) {
	upper := strings.ToUpper(name)
	for _, p := range patterns {
		if strings.Contains(upper, strings.ToUpper(p)) {
			return p, true
		}
	}
	return "", false
}
