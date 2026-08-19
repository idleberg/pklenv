package cli

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"

	"github.com/mattn/go-isatty"
	"github.com/spf13/cobra"

	"github.com/idleberg/pklenv/internal/config"
	"github.com/idleberg/pklenv/internal/envfile"
	"github.com/idleberg/pklenv/internal/perm"
	"github.com/idleberg/pklenv/internal/redact"
	"github.com/idleberg/pklenv/internal/warn"
)

type emitOptions struct {
	outDir      string
	force       bool
	interactive bool
	strict      bool
	verbose     bool
}

func newEmitCmd(io *IO, perms *perm.Set) *cobra.Command {
	var opts emitOptions

	cmd := &cobra.Command{
		Use:   "emit [FILE]",
		Short: "Evaluate configs and write flat .env files",
		Long: strings.TrimSpace(`
Evaluate a Pkl config and write the corresponding .env file.

With no FILE, every env*.pkl file in the directory is discovered and written to
its dotenv pendant (env.pkl -> .env, env.production.pkl -> .env.production).
Passing a FILE restricts emit to that one config.

Discovery never combines files. Merging happens only through a config's own
explicit "amends" declaration, which Pkl resolves during evaluation. A config
that fails is reported and skipped rather than cancelling the rest; the run
still exits non-zero.

A config may read the environment during evaluation with read("env:NAME"), or
select from it in bulk with read*("env:PREFIX_*").`),
		Args: cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			var file string
			if len(args) == 1 {
				file = args[0]
			}
			io.Verbose = opts.verbose
			return runEmit(cmd, io, file, opts, perms)
		},
	}

	f := cmd.Flags()
	f.StringVar(&opts.outDir, "outdir", "", "directory to write .env files into (default: alongside the config)")
	f.BoolVar(&opts.force, "force", false, "overwrite existing files without prompting")
	f.BoolVarP(&opts.interactive, "interactive", "i", false, "pick which discovered configs to emit from a list")
	f.BoolVar(&opts.strict, "strict", strictDefault(),
		"treat unredacted sensitive-looking names as an error (also settable with "+strictEnv+")")
	f.BoolVarP(&opts.verbose, "verbose", "v", false, "verbose output")

	return cmd
}

func runEmit(cmd *cobra.Command, io *IO, file string, opts emitOptions, perms *perm.Set) error {
	ctx := cmd.Context()

	warnStrictEnv(io, io.newLogger(opts.verbose))

	if opts.interactive && file != "" {
		return withHint(
			errors.New("--interactive picks from the discovered configs, but a FILE was named"),
			"drop the FILE to choose from a list, or drop --interactive to emit just that one")
	}

	sources, err := resolveSources(file)
	if err != nil {
		return err
	}
	if len(sources) == 0 {
		return withHint(
			errors.New("no env*.pkl config found in this directory"),
			"create env.pkl, or name a config explicitly: pklenv emit path/to/env.pkl")
	}

	if opts.interactive {
		sources, err = selectSources(cmd, io, sources)
		if err != nil {
			return err
		}
		if len(sources) == 0 {
			// Not an error: an empty checklist is an answer, and the user gave
			// it deliberately. Saying so beats exiting silently, which reads
			// like the picker failed.
			io.newLogger(opts.verbose).Info("nothing selected; no files written")
			return nil
		}
	}

	// One bad config does not cancel the others. Discovery treats files as
	// independent — nothing pklenv does merges them, that is what `amends` is
	// for — so stopping at the first failure hides every later problem behind
	// it and turns a CI run into a fix-and-retry cycle, one config per
	// iteration. Each failure is reported where it happens and the run still
	// exits non-zero, so the partial set of written files is announced rather
	// than passed off as success.
	var failed int
	for _, src := range sources {
		if err := emitOne(ctx, cmd, io, src, opts, perms); err != nil {
			// A single config, named or discovered, has nothing to carry on
			// with: returning the error reads better than reporting it and then
			// summarizing a count of one.
			if len(sources) == 1 {
				return err
			}
			// Printed outside that config's masker, which is safe because
			// nothing raised past the point the masker is installed carries a
			// value — those errors name variables, paths and counts. The one
			// error that can quote a value is Pkl's own, and it is raised
			// before any value has been classified, which is what reportFatal's
			// summarizing exists for.
			reportFatal(io, err)
			failed++
		}
	}
	if failed > 0 {
		return fmt.Errorf("%d of %d configs failed", failed, len(sources))
	}
	return nil
}

// selectSources narrows the discovered configs to the ones the user ticks.
//
// Labelled with both ends of the mapping, because that mapping is the decision:
// "env.production.pkl" says which config, "-> .env.production" says which file
// on disk is about to be written, and only the second one can be destructive.
func selectSources(cmd *cobra.Command, stdio *IO, sources []config.Source) ([]config.Source, error) {
	if !stdio.canPrompt() {
		return nil, withHint(
			errors.New("--interactive needs a terminal to show the list on"),
			"drop --interactive to emit every discovered config, or name one: pklenv emit env.pkl")
	}

	labels := make([]string, len(sources))
	for i, src := range sources {
		labels[i] = fmt.Sprintf("%s → %s", filepath.Base(src.Path), src.Target)
	}

	// The unmasked stream, for the reason given on confirmOverwrite. Nothing
	// here can carry a value either: these are filenames, and no config has
	// been evaluated yet.
	_, rawErr := stdio.Raw()
	chosen, err := stdio.pick(cmd.InOrStdin(), rawErr, "Emit which configs?", labels)
	if err != nil {
		if errors.Is(err, errDeclined) {
			return nil, nil
		}
		return nil, err
	}

	// Indices rather than the labels, so selection order does not reshuffle
	// discovery order — the same reason Config.Names sorts.
	picked := make([]config.Source, 0, len(chosen))
	for i := range sources {
		if slices.Contains(chosen, i) {
			picked = append(picked, sources[i])
		}
	}
	return picked, nil
}

func resolveSources(file string) ([]config.Source, error) {
	if file == "" {
		return config.Discover(".")
	}
	src, err := config.Describe(file)
	if err != nil {
		return nil, err
	}
	return []config.Source{src}, nil
}

func emitOne(ctx context.Context, cmd *cobra.Command, io *IO, src config.Source, opts emitOptions, perms *perm.Set) error {
	if err := ensureSchema(io, src.Path, opts.verbose); err != nil {
		return err
	}

	cfg, err := config.Load(ctx, src.Path, config.Options{Perm: *perms})
	if err != nil {
		return err
	}

	// Mask before anything else is printed: an error raised past this point
	// could otherwise quote a resolved value.
	secrets := cfg.SecretValues()
	masker := redact.New(secrets)
	// Restored on the way out rather than left in place: emit runs this loop
	// once per discovered config, and see IO.Redact for what happens when the
	// wrapping is allowed to stack.
	defer io.Redact(masker)()
	io.maskForCI(secrets)
	io.learn(cfg.Names(), secrets)

	log := io.newLogger(opts.verbose)

	if err := reportWarnings(io, log, cfg, warn.Scan(cfg.Decisions, nil), opts.strict); err != nil {
		return err
	}

	names := cfg.Names()
	for _, n := range names {
		if err := envfile.ValidateName(n); err != nil {
			return withHint(
				fmt.Errorf("in %s: %w", filepath.Base(src.Path), err),
				"a .env file cannot round-trip this name; rename the variable in the config")
		}
	}

	dir := opts.outDir
	if dir == "" {
		dir = filepath.Dir(src.Path)
	}
	target := filepath.Join(dir, src.Target)

	if err := confirmOverwrite(cmd, io, target, opts.force); err != nil {
		return err
	}

	content := envfile.Render(names, func(n string) string { return cfg.Vars[n].Value },
		fmt.Sprintf("generated by pklenv from %s\ndo not edit; edit the .pkl config instead", filepath.Base(src.Path)))

	// 0600: this file may hold secrets, and the default 0644 would make them
	// world-readable on a shared machine.
	if err := os.WriteFile(target, []byte(content), 0o600); err != nil {
		return fmt.Errorf("writing %s: %w", target, err)
	}

	redacted := 0
	for _, d := range cfg.Decisions {
		if d == redact.Redacted {
			redacted++
		}
	}
	log.Info("wrote "+target, "vars", len(names), "redacted", redacted)
	return nil
}

// confirmOverwrite guards an existing file.
//
// The no-TTY case must require --force explicitly rather than defaulting to
// either answer: defaulting to yes silently destroys a file in CI, and
// defaulting to no makes CI runs fail in a way that looks like a bug.
func confirmOverwrite(cmd *cobra.Command, stdio *IO, target string, force bool) error {
	if force {
		return nil
	}
	if _, err := os.Stat(target); err != nil {
		return nil // nothing to overwrite
	}

	if !stdio.canPrompt() {
		return withHint(
			fmt.Errorf("%s already exists and there is no terminal to confirm on", target),
			"pass --force to overwrite it")
	}

	// Written to the unmasked stream. The masker buffers by line, and a form
	// redraws in place without ever emitting one, so a masked prompt would sit
	// in the buffer unseen while the read blocks — the user sees nothing and
	// pklenv looks hung. Nothing here can carry a value: it is a path pklenv
	// was given.
	_, rawErr := stdio.Raw()
	ok, err := stdio.confirm(cmd.InOrStdin(), rawErr,
		fmt.Sprintf("%s exists. Overwrite?", target), "Overwrite", "Keep")
	if err != nil && !errors.Is(err, errDeclined) {
		return fmt.Errorf("reading confirmation: %w", err)
	}
	if !ok || err != nil {
		return fmt.Errorf("declined overwriting %s", target)
	}
	return nil
}

// isTerminal reports whether f is attached to a terminal.
//
// A real isatty ioctl, not a character-device check: /dev/null is a character
// device but not a terminal, so the cheap check treats `pklenv emit </dev/null`
// as interactive and prompts into a void. That is precisely the CI case the
// no-TTY guarantee exists for.
//
// go-isatty is already in the module graph beneath charmbracelet/log, so this
// costs no additional dependency.
func isTerminal(f *os.File) bool {
	return isatty.IsTerminal(f.Fd()) || isatty.IsCygwinTerminal(f.Fd())
}
