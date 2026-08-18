// Package cli wires pklenv's command surface.
package cli

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strings"

	"github.com/spf13/cobra"

	"github.com/idleberg/pklenv/internal/config"
)

// version is overridden at build time via -ldflags.
var version = "dev"

// strictEnv turns --strict on for every invocation in an environment, so a CI
// job declares it once rather than repeating the flag on each command.
const strictEnv = "PKLENV_STRICT"

// strictSetting reports whether the environment asks for --strict, and whether
// it asked in a spelling pklenv recognizes.
//
// Deliberately its own variable rather than an inference from CI. --strict puts
// a heuristic in the enforcement path, and the pattern list it draws on is
// expected to grow: inferring it from an ambient CI flag would turn every
// future addition to that list into a broken pipeline for configs nobody
// touched. Set explicitly, the strictness is the user's declaration, and it
// reproduces locally by exporting the same variable.
//
// Anything that is not an explicit falsehood counts as on. A variable whose
// whole purpose is to tighten a check must not loosen it silently, so a
// mistyped PKLENV_STRICT=ture still fails the run rather than quietly stopping
// the checking. That is the safe answer and a confusing one, which is what the
// second return value is for: the caller warns, and the behaviour is unchanged.
func strictSetting() (on, recognized bool) {
	switch strings.ToLower(strings.TrimSpace(os.Getenv(strictEnv))) {
	case "":
		return false, true
	case "1", "true", "yes", "on":
		return true, true
	case "0", "false", "no", "off":
		return false, true
	default:
		return true, false
	}
}

// strictDefault is strictSetting's answer alone, for the flag default.
//
// Nothing here may print. It runs at command-construction time, once per
// subcommand, before IO has been wired for masking — a warning from here would
// print twice and outside the masker.
func strictDefault() bool {
	on, _ := strictSetting()
	return on
}

// warnStrictEnv reports a PKLENV_STRICT value pklenv does not recognize.
//
// Called from a command's RunE rather than from strictDefault, for the reason
// given there. It names the value because that is the whole diagnostic: the
// difference between "ture" and "true" is invisible until something points at
// it. Printing it is safe — this is pklenv's own variable, not a config value.
func warnStrictEnv(stdio *IO, l *logger) {
	if _, recognized := strictSetting(); recognized {
		return
	}
	l.Warn(fmt.Sprintf("unrecognized %s value %q; treating it as on", strictEnv, os.Getenv(strictEnv)))
	stdio.hint("use 1, true, yes or on to enable it, or 0, false, no or off to disable it")
}

// NewRootCmd builds the command tree.
func NewRootCmd(io *IO) *cobra.Command {
	root := &cobra.Command{
		Use:           "pklenv",
		Short:         "Typed, cascading environment config backed by Pkl",
		Long:          "pklenv evaluates .pkl files as the source of truth for environment config, injecting the result into a child process (run) or writing flat .env files (emit).",
		Version:       version,
		SilenceUsage:  true,
		SilenceErrors: true,
	}

	root.AddCommand(newRunCmd(io), newEmitCmd(io))

	// Cobra names its generated command "completion", singular. It emits one
	// script per invocation but the thing being installed is a set of
	// completions, and every shell that ships a directory for them spells it in
	// the plural. Renaming has to happen after the command exists, so it is
	// forced into existence rather than waiting for the first --help.
	root.InitDefaultCompletionCmd()
	for _, c := range root.Commands() {
		if c.Name() == "completion" {
			c.Use = strings.Replace(c.Use, "completion", "completions", 1)
			// The old spelling still works, so anything already wired to it —
			// a dotfile, a packaging script — keeps working.
			c.Aliases = append(c.Aliases, "completion")
			// Each shell's help embeds "pklenv completion <shell>" as a literal
			// in its Long. Left alone it would hand the user a command spelled
			// differently from the one they just ran.
			for _, shell := range c.Commands() {
				shell.Long = strings.ReplaceAll(shell.Long, root.Name()+" completion ", root.Name()+" completions ")
			}
		}
	}

	return root
}

// Main runs pklenv and returns the process exit code.
func Main(ctx context.Context, args []string) int {
	io := StdIO()
	io.pad()
	root := NewRootCmd(io)
	root.SetArgs(args)

	err := root.ExecuteContext(ctx)
	if err == nil {
		io.Close()
		return 0
	}

	// A child's exit status is mirrored rather than reported: `pklenv run` is a
	// wrapper, and a caller inspecting $? wants the child's answer, not ours.
	var exitErr *ExitError
	if errors.As(err, &exitErr) {
		io.Close()
		return exitErr.Code
	}

	// Reported before Close, and through io.Err rather than os.Stderr, so the
	// masker still covers the last thing printed. Writing to os.Stderr after
	// Close would put the one message most likely to quote a value outside the
	// only thing that would have caught it.
	reportFatal(io, err)
	io.Close()
	return 1
}

// reportFatal prints the error that ended the run.
//
// Pkl's own diagnostics are summarized unless there is a terminal to read them
// on or --verbose asked for them: they carry a source excerpt that can quote
// values, and unlike everything else pklenv prints, that excerpt cannot be
// masked — the evaluation failed, so no value was ever classified. A CI log
// keeps what it is given, so the default there is the classification alone.
func reportFatal(io *IO, err error) {
	l := io.newLogger(io.Verbose)

	var evalErr *config.EvalError
	if errors.As(err, &evalErr) {
		summarized := !io.Verbose && !io.ErrIsTerminal()
		if summarized {
			l.Error(evalErr.Summary())
		} else {
			l.Error(err.Error())
		}
		// A hint about the config beats a hint about the CLI: if Pkl said
		// something specific enough to act on, that is the more useful line.
		if h := evalErr.Hint(); h != "" {
			io.hint(h)
		} else if summarized {
			io.hint("run with --verbose for the full Pkl diagnostic, which may quote values")
		}
		return
	}

	l.Error(err.Error())

	var hinted hinter
	if errors.As(err, &hinted) {
		io.hint(hinted.Hint())
	}
}
