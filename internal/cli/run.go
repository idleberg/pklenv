package cli

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"os/signal"
	"strings"
	"syscall"

	"github.com/spf13/cobra"

	"github.com/idleberg/pklenv/internal/config"
	"github.com/idleberg/pklenv/internal/envfile"
	"github.com/idleberg/pklenv/internal/redact"
	"github.com/idleberg/pklenv/internal/warn"
)

type runOptions struct {
	file    string
	raw     bool
	strict  bool
	verbose bool
}

func newRunCmd(stdio *IO) *cobra.Command {
	var opts runOptions

	cmd := &cobra.Command{
		Use:   "run [flags] -- COMMAND [ARGS...]",
		Short: "Evaluate a config and run a command with it in the environment",
		Long: strings.TrimSpace(`
Evaluate a Pkl config and inject the resolved values into a child process's
environment. Nothing is written to disk.

The child's stdout and stderr are piped through pklenv so that redacted values
are masked in its output too. That costs the child its terminal: colours and
interactive prompts may misbehave. Pass --raw to hand over the streams
untouched, which disables masking of the child's output.`),
		// Cobra's own "requires at least 1 arg(s), only received 0" names neither
		// what is missing nor where it goes, and the answer is not guessable:
		// the command belongs after a -- separator.
		Args: func(_ *cobra.Command, args []string) error {
			if len(args) == 0 {
				return withHint(
					errors.New("run needs a command to execute"),
					"the command goes after a -- separator: pklenv run -- npm start")
			}
			return nil
		},
		RunE: func(cmd *cobra.Command, args []string) error {
			stdio.Verbose = opts.verbose
			return runRun(cmd, stdio, args, opts)
		},
	}

	f := cmd.Flags()
	f.StringVarP(&opts.file, "file", "f", "env.pkl", "config file to evaluate")
	f.BoolVar(&opts.raw, "raw", false,
		"pass the child's stdout/stderr through untouched, disabling masking of its output")
	f.BoolVar(&opts.strict, "strict", strictDefault(),
		"treat unredacted sensitive-looking names as an error (also settable with "+strictEnv+")")
	f.BoolVarP(&opts.verbose, "verbose", "v", false, "verbose output")

	return cmd
}

// ExitError carries a child process's exit status so main can mirror it.
type ExitError struct{ Code int }

func (e *ExitError) Error() string { return fmt.Sprintf("child exited with status %d", e.Code) }

func runRun(cmd *cobra.Command, stdio *IO, args []string, opts runOptions) error {
	ctx := cmd.Context()

	warnStrictEnv(stdio, stdio.newLogger(opts.verbose))

	cfg, err := config.Load(ctx, opts.file, config.Options{})
	if err != nil {
		return err
	}

	secrets := cfg.SecretValues()
	masker := redact.New(secrets)
	defer stdio.Redact(masker)()

	// Register with the CI system before anything runs. This is the only
	// guarantee that survives --raw, since pklenv is not in the child's output
	// path in that mode.
	stdio.maskForCI(secrets)
	stdio.learn(cfg.Names(), secrets)

	log := stdio.newLogger(opts.verbose)

	if err := reportWarnings(stdio, log, cfg, warn.Scan(cfg.Decisions, nil), opts.strict); err != nil {
		return err
	}

	names := cfg.Names()
	for _, n := range names {
		if err := envfile.ValidateName(n); err != nil {
			return err
		}
	}

	if opts.raw && !masker.Empty() {
		log.Warn("--raw: the child's output is not masked; redacted values may appear in its logs")
	}

	log.Debug("injecting variables", "count", len(names), "config", cfg.Path)

	child := exec.CommandContext(ctx, args[0], args[1:]...)
	child.Env = mergeEnv(os.Environ(), cfg, names)
	child.Stdin = os.Stdin

	if opts.raw {
		child.Stdout, child.Stderr = stdio.Raw()
	} else {
		// The same masking writers pklenv uses for its own output, so the
		// child's stream and pklenv's share one flush point and one mutex
		// rather than interleaving through two independent buffers.
		child.Stdout, child.Stderr = stdio.Out, stdio.Err
	}

	return execChild(child)
}

// mergeEnv layers the config's variables over the ambient environment.
//
// The config wins: injecting a value that the surrounding shell then overrides
// would make the whole tool unreliable.
func mergeEnv(ambient []string, cfg *config.Config, names []string) []string {
	override := make(map[string]struct{}, len(names))
	for _, n := range names {
		override[n] = struct{}{}
	}

	out := make([]string, 0, len(ambient)+len(names))
	for _, kv := range ambient {
		name, _, ok := strings.Cut(kv, "=")
		if !ok {
			continue
		}
		if _, replaced := override[name]; replaced {
			continue
		}
		out = append(out, kv)
	}
	for _, n := range names {
		out = append(out, n+"="+cfg.Vars[n].Value)
	}
	return out
}

// execChild runs the child, forwards signals to it, and mirrors its exit status.
func execChild(child *exec.Cmd) error {
	if err := child.Start(); err != nil {
		return fmt.Errorf("starting %s: %w", child.Path, err)
	}

	// Forward the signals a user or supervisor would send. Without this, Ctrl-C
	// kills pklenv and orphans the child, which is the behaviour people notice
	// first in a wrapper.
	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, os.Interrupt, syscall.SIGTERM, syscall.SIGHUP, syscall.SIGQUIT)
	done := make(chan struct{})
	go func() {
		for {
			select {
			case s := <-sigs:
				if child.Process != nil {
					_ = child.Process.Signal(s)
				}
			case <-done:
				return
			}
		}
	}()
	defer func() {
		signal.Stop(sigs)
		close(done)
	}()

	err := child.Wait()

	if err != nil {
		var exitErr *exec.ExitError
		if errors.As(err, &exitErr) {
			return &ExitError{Code: exitErr.ExitCode()}
		}
		return fmt.Errorf("running %s: %w", child.Path, err)
	}
	return nil
}
