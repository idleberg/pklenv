package cli

import (
	"strings"
	"testing"
)

// plainIO renders through the ASCII profile, so decorate's decisions show up as
// where it split the string rather than as escape sequences.
func markingIO(t *testing.T) *IO {
	t.Helper()
	return &IO{Out: &strings.Builder{}, Err: &strings.Builder{}}
}

// matches reports what decorate would colour, by matching against the same
// pattern decorate uses. Asserting on the matches rather than on rendered
// output keeps the test about the rule and not about a colour number.
func matches(stdio *IO, msg string) []string {
	re := stdio.refs
	if re == nil {
		re = defaultRefs
	}
	return re.FindAllString(msg, -1)
}

func TestDecorateMatchesFilesAndNames(t *testing.T) {
	stdio := markingIO(t)

	cases := []struct {
		msg  string
		want []string
	}{
		{
			"missing.pkl is not a pklenv config: expected env.pkl or env.<environment>.pkl",
			[]string{"missing.pkl", "env.pkl", "env.<environment>.pkl"},
		},
		{"wrote .env", []string{".env"}},
		{"wrote .env.production", []string{".env.production"}},
		{"no env*.pkl config found in this directory", []string{"env*.pkl"}},
		{"create env.pkl, or name a config explicitly: pklenv emit path/to/env.pkl",
			[]string{"env.pkl", "path/to/env.pkl"}},
		{"at pklenv.PklEnv#resolved (file:///tmp/env.unset.pkl)",
			[]string{"file:///tmp/env.unset.pkl"}},
		{"you might leak sensitive values: DB_PASSWORD, API_TOKEN",
			[]string{"DB_PASSWORD", "API_TOKEN"}},
		{"Cannot find resource `env:PKLENV_TEST_SECRET`", []string{"PKLENV_TEST_SECRET"}},

		// The prose pklenv writes is full of capitalised words that are not
		// variables. Requiring an underscore is what keeps them uncoloured.
		{"run needs a command to execute", nil},
		{"the command goes after a -- separator: pklenv run -- npm start", nil},
		{"emit [FILE] runs on CI too", nil},
		{"pass --force to overwrite it", nil},
	}

	for _, tc := range cases {
		got := matches(stdio, tc.msg)
		if len(got) != len(tc.want) {
			t.Errorf("%q\n got %q\nwant %q", tc.msg, got, tc.want)
			continue
		}
		for i := range got {
			if got[i] != tc.want[i] {
				t.Errorf("%q\n got %q\nwant %q", tc.msg, got, tc.want)
				break
			}
		}
	}
}

// A name the shape rule cannot reach is still known, because the config
// declared it.
func TestDecorateLearnsDeclaredNames(t *testing.T) {
	stdio := markingIO(t)

	if got := matches(stdio, "PORT is not set"); len(got) != 0 {
		t.Errorf("PORT should not match on shape alone, got %q", got)
	}

	stdio.learn([]string{"PORT", "DEBUG"}, nil)
	if got := matches(stdio, "PORT is not set"); len(got) != 1 || got[0] != "PORT" {
		t.Errorf("PORT should match once declared, got %q", got)
	}
}

// A short name must not claim the head of a longer one and leave the rest
// uncoloured.
func TestDecoratePrefersLongerNames(t *testing.T) {
	stdio := markingIO(t)
	stdio.learn([]string{"DB", "DB_PASSWORD"}, nil)

	got := matches(stdio, "DB_PASSWORD leaks")
	if len(got) != 1 || got[0] != "DB_PASSWORD" {
		t.Errorf("expected the whole name, got %q", got)
	}
}

// Colour inserted inside a secret would split it, and the masker searches for
// the literal bytes — the value would print in full.
//
// Asserted on the guard rather than on decorate's output: a test IO is not a
// terminal, so the ASCII profile emits no escapes and a rendered string cannot
// show whether the colour was suppressed or merely invisible.
func TestDecorateSkipsSecrets(t *testing.T) {
	stdio := markingIO(t)
	stdio.learn(nil, []string{"PROD_KEY_1", ""})

	// The shape rule matches this, so without the guard it would be coloured
	// mid-value and the masker would stop recognising it.
	if !stdio.skipSecret("PROD_KEY_1") {
		t.Error("a match that is the secret must be skipped")
	}
	if !stdio.skipSecret("PROD_KEY") {
		t.Error("a match inside the secret must be skipped too — it splits the value just as well")
	}
	if stdio.skipSecret("API_TOKEN") {
		t.Error("an unrelated name must still be coloured")
	}
	// An empty secret is in every string; treating it as a match would disable
	// decoration entirely.
	if stdio.skipSecret("anything") {
		t.Error("an empty secret must not suppress everything")
	}
}
