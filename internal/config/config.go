// Package config discovers, evaluates and normalizes pklenv's Pkl configs.
package config

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"

	"github.com/apple/pkl-go/pkl"

	"github.com/idleberg/pklenv/internal/perm"
	"github.com/idleberg/pklenv/internal/redact"
)

// Var is one environment variable as the Pkl module's `resolved` mapping
// presents it.
type Var struct {
	Value string `pkl:"value"`

	// Redact is tri-state on purpose. nil means undeclared — the redaction
	// globs decide, and the name is eligible for the sensitive-name warning.
	// An explicit false is a recorded decision, not an absence of one.
	Redact *bool `pkl:"redact"`
}

// Module is the evaluated shape of a pklenv config.
type Module struct {
	Resolved   map[string]Var `pkl:"resolved"`
	Redactions []string       `pkl:"redactions"`
}

// Config is an evaluated config together with its provenance and the redaction
// decisions derived from it.
type Config struct {
	// Path is the .pkl file this was evaluated from.
	Path string

	// Vars maps variable names to values, ready to inject or write.
	Vars map[string]Var

	// Decisions records the redaction state of every variable in Vars.
	//
	// The glob list itself is not carried: it has already been applied here,
	// and a second copy of the rules invites a caller to re-derive an answer
	// that must only be reached in one place.
	Decisions map[string]redact.Decision
}

// Names returns the variable names in sorted order.
//
// Go maps do not preserve Pkl's declaration order, so pklenv sorts instead of
// emitting whatever order a map iteration happens to produce — a .env file that
// reshuffles on every run is unreadable in a diff.
func (c *Config) Names() []string {
	names := make([]string, 0, len(c.Vars))
	for n := range c.Vars {
		names = append(names, n)
	}
	sort.Strings(names)
	return names
}

// SecretValues returns the values that must be masked in output.
func (c *Config) SecretValues() []string {
	var out []string
	for name, v := range c.Vars {
		if c.Decisions[name] == redact.Redacted {
			out = append(out, v.Value)
		}
	}
	return out
}

// Options controls evaluation.
type Options struct {
	// Env is the ambient environment to draw from. nil means the process's own.
	Env []string

	// Perm is what the config is permitted to reach. The zero value is the
	// default posture: no network, file reads confined to Perm.RootDir, every
	// environment variable readable.
	Perm perm.Set
}

// EvalError is a failure reported by Pkl itself, as opposed to one pklenv
// raised about a config.
//
// It is distinguished because Pkl's diagnostics quote source, and source
// includes values: a violated constraint prints `Value: "tok_supersecret"`.
// That cannot be masked — the evaluation failed, so pklenv never learned which
// values were secret — so the caller is given the choice of how much to print.
type EvalError struct {
	// File is the config being evaluated, for the summary line.
	File string

	// Err is Pkl's full diagnostic.
	Err error
}

// Error scrubs before it prints. This is the path --verbose and a terminal take,
// so leaving it unscrubbed would mean the guarantee held only in CI — which is
// exactly backwards, since a CI log is the copy that persists.
func (e *EvalError) Error() string {
	return fmt.Sprintf("evaluating %s: %v", e.File, scrubRefusals(e.Err.Error()))
}

// Unwrap returns the diagnostic as Pkl wrote it. Callers that print must go
// through Error or Summary; this exists for errors.Is and errors.As.
func (e *EvalError) Unwrap() error { return e.Err }

// Hint returns the action that resolves this failure, or "" when there isn't
// one worth guessing at.
//
// Matching on Pkl's message text is unlovely, but the alternative is silence in
// the cases where the fix is entirely knowable. Each pattern here is checked
// against a real diagnostic, and a miss costs nothing — the error still prints
// in full.
func (e *EvalError) Hint() string {
	msg := e.Err.Error()
	switch {
	// Refusals come first: they are pklenv's own doing, and their answer is a
	// flag rather than a change to the config. Which flag depends on the scheme
	// that was refused, not on which allowlist reported it — `env:` and
	// `https:` are both resources, and pointing an environment problem at
	// --allow-net would send the user somewhere useless.
	case strings.Contains(msg, "allowlist") && refusedScheme(msg) == "env":
		return fmt.Sprintf("--%s does not grant %s; add it, or drop the flag to allow every variable",
			perm.FlagAllowEnv, refusedName(msg))
	case strings.Contains(msg, "module allowlist"), strings.Contains(msg, "resource allowlist"):
		if host := refusedHost(msg); host != "" {
			return fmt.Sprintf("pklenv does not allow network access by default; pass --%s=%s to permit it",
				perm.FlagAllowNet, host)
		}
		return fmt.Sprintf("pklenv does not allow network access by default; pass --%s=HOST to permit it",
			perm.FlagAllowNet)
	case strings.Contains(msg, "root directory"):
		return fmt.Sprintf("file reads are confined to the working directory; pass --%s=DIR to widen it, or --%s='' to disable the boundary",
			perm.FlagRootDir, perm.FlagRootDir)
	case strings.Contains(msg, "Cannot find resource `env:"):
		return fmt.Sprintf("that variable is either unset or not permitted by --%s; use read?(\"env:NAME\") for one that may be absent",
			perm.FlagAllowEnv)
	case strings.Contains(msg, "Cannot find module"):
		return "check the path in the amends or import line; it resolves relative to this file, not the working directory"
	case strings.Contains(msg, "Cannot find property"):
		return "check the property name against the schema this config amends"
	// Matching on the schema's own EnvName pattern rather than on "Type
	// constraint violated" generally: that message covers every constraint in
	// the module, and only this one has an answer that fits on a line.
	//
	// This literal is a copy of `EnvName` in schema/PklEnv.pkl, and the fragile
	// one of the rule's three copies: envfile.ValidateName would still agree
	// with a changed schema by being written to the same rule, but this hint
	// just stops appearing. TestHintFiresOnTheRealDiagnostic evaluates a bad
	// name through the real schema so the coupling fails loudly instead.
	case strings.Contains(msg, `[A-Za-z_][A-Za-z0-9_]*`):
		return "environment variable names take letters, digits and underscores, and cannot start with a digit"
	default:
		return ""
	}
}

// Summary returns the classification without the source excerpt.
//
// Pkl's diagnostics open with a value-free classification ("Cannot find module",
// "Type constraint violated") and follow it, after a blank line, with the
// excerpt that may quote values. Two rules cut it, because they fail
// differently: the blank line is where the excerpt starts, and a `Value:` line
// is the specific thing being kept out. If Pkl's format shifts, the first rule
// degrades to showing a little too much and the second still holds.
func (e *EvalError) Summary() string {
	var kept []string
	for _, line := range strings.Split(scrubRefusals(e.Err.Error()), "\n") {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" && len(kept) > 0 {
			break
		}
		if trimmed == "" || trimmed == "–– Pkl Error ––" {
			continue
		}
		if strings.HasPrefix(trimmed, "Value:") {
			continue
		}
		kept = append(kept, trimmed)
	}
	if len(kept) == 0 {
		return fmt.Sprintf("could not evaluate %s", e.File)
	}
	return fmt.Sprintf("%s: %s", e.File, strings.Join(kept, " "))
}

// ErrPklMissing reports that the pkl CLI could not be found.
//
// pkl-go evaluates by spawning `pkl server` and speaking its message-passing
// protocol, so the binary is a hard runtime requirement. Without this check the
// failure surfaces as a bare exec error naming a binary the user never invoked.
var ErrPklMissing = &missingPklError{}

type missingPklError struct{}

func (*missingPklError) Error() string {
	return "the `pkl` CLI is required but was not found on PATH"
}

func (*missingPklError) Hint() string {
	return "install it however you manage tools; see https://pkl-lang.org/main/current/pkl-cli"
}

// Load evaluates a single .pkl config file.
//
// One evaluator per call, built and closed here, so `emit` over N discovered
// configs starts N `pkl server` processes in sequence. Measured at ~12ms each
// against the native pkl distribution — linear and small enough that hoisting
// the evaluator into the caller would buy nothing today.
//
// The number belongs to the distribution rather than to pklenv, which is the
// part worth remembering: on the JVM jar, server startup is roughly two orders
// of magnitude slower and the same 20-config run takes tens of seconds. If that
// shows up, the change is contained — Load takes an evaluator, or gains a
// LoadAll — and it costs no semantics, since every config in a run already
// shares one ambient environment.
func Load(ctx context.Context, path string, opts Options) (*Config, error) {
	if _, err := exec.LookPath("pkl"); err != nil {
		return nil, ErrPklMissing
	}

	abs, err := filepath.Abs(path)
	if err != nil {
		return nil, fmt.Errorf("resolving %s: %w", path, err)
	}
	if _, err := os.Stat(abs); err != nil {
		return nil, fmt.Errorf("reading %s: %w", path, err)
	}

	ev, err := newEvaluator(ctx, opts)
	if err != nil {
		return nil, err
	}
	defer func() { _ = ev.Close() }()

	var mod Module
	if err := ev.EvaluateModule(ctx, pkl.FileSource(abs), &mod); err != nil {
		return nil, &EvalError{File: filepath.Base(abs), Err: err}
	}

	if err := redact.ValidateGlobs(mod.Redactions); err != nil {
		return nil, fmt.Errorf("in %s: %w", filepath.Base(abs), err)
	}

	cfg := &Config{
		Path:      abs,
		Vars:      mod.Resolved,
		Decisions: make(map[string]redact.Decision, len(mod.Resolved)),
	}
	for name, v := range mod.Resolved {
		cfg.Decisions[name] = redact.Decide(name, v.Redact, mod.Redactions)
	}
	return cfg, nil
}

// newEvaluator builds the evaluator a config is resolved with.
//
// pklenv once gated `read("env:NAME")` on a per-name grant declared inside the
// config, and removed it because it protected one of three channels: a config
// that is not trusted can equally read `file:` resources or execute code
// through a remote `package:` import, so restricting the environment alone
// implied a guarantee that was never there.
//
// That reasoning still holds, and is why perm.Set gates every channel at once
// rather than any one of them. With the network denied, the filesystem confined
// to a root, and the environment narrowable by name, a grant means what it
// appears to mean. The grant also now comes from the command line rather than
// from inside the file it governs, which is what makes it enforceable in a
// single pass — the old design had to evaluate a config to learn what that
// config was allowed to do.
//
// pkl.PreconfiguredOptions is deliberately not used. It *appends* its defaults
// to the allowlists, so any policy layered on top of it is an addition to
// "everything is permitted": it would read like a restriction while being none.
func newEvaluator(ctx context.Context, opts Options) (pkl.Evaluator, error) {
	ambient := opts.Env
	if ambient == nil {
		ambient = os.Environ()
	}

	return pkl.NewEvaluator(ctx, func(o *pkl.EvaluatorOptions) {
		opts.Perm.Apply(o)
		o.Env = envMap(ambient)
		o.Logger = pkl.NoopLogger
		o.CacheDir = cacheDir()
	})
}

// cacheDir is where `package:` modules are cached, matching the location the
// pkl CLI uses so a package fetched by either is reused by the other.
//
// Empty when the home directory is unknown, which disables caching rather than
// failing: pkl-go's own helper panics there, and an unreadable home is not a
// reason for pklenv to stop working.
func cacheDir() string {
	home, err := os.UserHomeDir()
	if err != nil {
		return ""
	}
	return filepath.Join(home, ".pkl/cache")
}

func envMap(environ []string) map[string]string {
	out := make(map[string]string, len(environ))
	for _, kv := range environ {
		for i := 0; i < len(kv); i++ {
			if kv[i] == '=' {
				out[kv[:i]] = kv[i+1:]
				break
			}
		}
	}
	return out
}
