package cli

import (
	"fmt"
	"io"
	"os"
	"regexp"
	"strings"

	"github.com/charmbracelet/lipgloss"
	"github.com/charmbracelet/log"
	"github.com/muesli/termenv"

	"github.com/idleberg/pklenv/internal/config"
	"github.com/idleberg/pklenv/internal/redact"
	"github.com/idleberg/pklenv/internal/warn"
)

// styleSet holds the styles pklenv applies to its own message text.
type styleSet struct {
	// hint dims a follow-up line, so it reads as secondary to the line above.
	hint lipgloss.Style
	// name picks a variable name out of a sentence.
	name lipgloss.Style
	// file picks a config or dotenv path out of a sentence.
	file lipgloss.Style
	// plain carries no properties. It is the base decorate uses for text that
	// is not otherwise styled, and it exists so that base always comes from the
	// stderr renderer rather than lipgloss's stdout-probing default.
	plain lipgloss.Style
}

// styles builds the styles against the real stderr rather than the global
// default renderer.
//
// lipgloss's package-level styles probe os.Stdout, which is the wrong stream
// and, once masking is in play, not the stream anything is written to either.
// A style built from the wrong stream renders escape sequences into a pipe, or
// renders nothing into a terminal — the two halves of the same bug.
func (stdio *IO) styles() styleSet {
	r := lipgloss.NewRenderer(os.Stderr)
	if !stdio.ErrIsTerminal() {
		r.SetColorProfile(termenv.Ascii)
	}
	return styleSet{
		hint: r.NewStyle().Faint(true),
		// Bold yellow: a variable name is the rarest noun pklenv prints and
		// usually the subject of the line it appears in, so it can afford the
		// louder of the two treatments.
		name: r.NewStyle().Bold(true).Foreground(lipgloss.Color("11")),
		// Cyan, and not bold: filenames appear in almost every line pklenv
		// prints, and a treatment loud enough for the rare variable name would
		// be noise at that frequency.
		file:  r.NewStyle().Foreground(lipgloss.Color("14")),
		plain: r.NewStyle(),
	}
}

// IO carries the streams a command writes to, so tests can capture them.
type IO struct {
	Out io.Writer
	Err io.Writer

	// Verbose is set by whichever subcommand is running, so the top-level error
	// handler can decide how much of a Pkl diagnostic to print. It lives here
	// because that decision is made in Main, after the subcommand's flags are
	// out of scope.
	Verbose bool

	// rawOut and rawErr are Out and Err before masking was applied.
	//
	// Two things may use them, both deliberately outside the masker:
	//
	//   - the CI masking directives, which have to carry the literal value to
	//     register it with the CI system; sending those through the masker
	//     would rewrite them to "::add-mask::[redacted]" and silently disable
	//     the very masking they exist to enable;
	//   - `run --raw`, where the user has explicitly traded masking of the
	//     child's output for a faithful terminal.
	rawOut io.Writer
	rawErr io.Writer

	// closers are the masking writers wrapping Out and Err, flushed by Close.
	closers []io.Closer

	// refs matches the variable names and paths decorate colours, and secrets
	// are the values it must leave alone. Both are set by learn once a config
	// is known; until then decorate falls back to shape alone.
	refs    *regexp.Regexp
	secrets []string
}

// StdIO returns the process's real streams.
func StdIO() *IO {
	return &IO{Out: os.Stdout, Err: os.Stderr, rawOut: os.Stdout, rawErr: os.Stderr}
}

// Raw returns the unmasked streams.
func (io *IO) Raw() (out, err io.Writer) {
	out, err = io.rawOut, io.rawErr
	if out == nil {
		out = io.Out
	}
	if err == nil {
		err = io.Err
	}
	return out, err
}

// Redact routes both streams through the masker and returns the call that puts
// them back.
//
// Everything pklenv prints after this point is masked, which is why it is
// applied as early as a config is known — an error raised between evaluation
// and this call could quote a resolved value.
//
// The restore has to be deferred by every caller, because `emit` calls this
// once per discovered config. Without it the wrapping accumulates: the second
// config's output would pass through the first config's masker as well as its
// own, and only the outermost writer would ever be flushed, leaving an
// unterminated line stranded in an inner buffer. Restoring also makes the
// cross-config masking a decision rather than an accident — each config is
// masked with its own values and nothing else.
func (io *IO) Redact(m *redact.Masker) (restore func()) {
	if m.Empty() {
		return func() {}
	}
	if io.rawOut == nil {
		io.rawOut = io.Out
	}
	if io.rawErr == nil {
		io.rawErr = io.Err
	}
	prevOut, prevErr := io.Out, io.Err
	outW := m.Writer(io.Out)
	errW := m.Writer(io.Err)
	io.Out, io.Err = outW, errW
	// Registered with Close as well, so a caller that exits without restoring
	// still flushes rather than dropping buffered output.
	io.closers = append(io.closers, outW, errW)

	return func() {
		_ = outW.Close()
		_ = errW.Close()
		io.Out, io.Err = prevOut, prevErr
		if n := len(io.closers); n >= 2 && io.closers[n-1] == errW && io.closers[n-2] == outW {
			io.closers = io.closers[:n-2]
		}
	}
}

// Close flushes any masked output still held back.
func (io *IO) Close() {
	for _, c := range io.closers {
		_ = c.Close()
	}
	io.closers = nil
}

// pad opens a blank line above everything pklenv prints.
//
// It runs before the command tree does, so the gap is there whether what
// follows is a log line, a Pkl diagnostic, or the help text — the separation
// belongs to the invocation, not to any one thing that might come out of it.
//
// Terminal only: the gap separates the output from the prompt the user just
// typed at, and a log file has no prompt — there it would be a stray empty line
// at the top of every job. Written to stderr because stdout may be piped into
// something that parses it, and unmasked because nothing has been classified
// this early.
func (stdio *IO) pad() {
	if !stdio.ErrIsTerminal() {
		return
	}
	w := stdio.rawErr
	if w == nil {
		w = stdio.Err
	}
	_, _ = fmt.Fprintln(w)
}

// ErrIsTerminal reports whether the real stderr behind any masking is a
// terminal.
//
// Two things need this, and neither can ask the writer directly once masking is
// in play: the logger's color profile, and how much of a Pkl diagnostic to
// print.
func (io *IO) ErrIsTerminal() bool {
	w := io.rawErr
	if w == nil {
		w = io.Err
	}
	f, ok := w.(*os.File)
	return ok && isTerminal(f)
}

// newLogger builds the leveled logger, writing to the (possibly masked) stream.
//
// The color profile has to be set explicitly. charm log derives one by probing
// the writer it is given (lipgloss.NewRenderer(w) internally), and the writer it
// is given here is a masking wrapper rather than the terminal — so left alone it
// concludes there is no terminal and drops all color the moment a config
// declares any redactions.
func (stdio *IO) newLogger(verbose bool) *logger {
	l := log.NewWithOptions(stdio.Err, log.Options{ReportTimestamp: false})
	if !stdio.ErrIsTerminal() {
		l.SetColorProfile(termenv.Ascii)
	} else {
		l.SetColorProfile(termenv.NewOutput(os.Stderr).ColorProfile())
	}
	if verbose {
		l.SetLevel(log.DebugLevel)
	}
	return &logger{Logger: l, stdio: stdio}
}

// logger colours the nouns in every message it prints.
//
// A wrapper rather than a helper at each call site, because "remember to call
// decorate" is a rule that holds until someone adds a message and forgets. The
// embedded *log.Logger is still reachable, so bypassing the decoration stays
// possible — and has to be spelled out where it happens.
//
// Only the message is touched. charm log renders fields as data, quoting
// anything with control characters in it, so a coloured field arrives as
// config="\x1b[36menv.pkl\x1b[0m".
type logger struct {
	*log.Logger
	stdio *IO
}

func (l *logger) Debug(msg any, kv ...any) { l.Logger.Debug(l.decorate(msg), kv...) }
func (l *logger) Info(msg any, kv ...any)  { l.Logger.Info(l.decorate(msg), kv...) }
func (l *logger) Warn(msg any, kv ...any)  { l.Logger.Warn(l.decorate(msg), kv...) }
func (l *logger) Error(msg any, kv ...any) { l.Logger.Error(l.decorate(msg), kv...) }

// decorate leaves anything that is not a string alone: charm log accepts any
// value as a message, and formatting one here would change how it prints.
func (l *logger) decorate(msg any) any {
	s, ok := msg.(string)
	if !ok {
		return msg
	}
	return l.stdio.decorate(l.stdio.styles().plain, s)
}

// hinter is implemented by errors that know what to do about themselves.
//
// An interface rather than a concrete type so any package can carry a hint
// without importing this one. reportFatal prints it under the error.
type hinter interface {
	Hint() string
}

// hintedError attaches the resolving action to an error.
//
// The hint is deliberately separate from the message rather than appended to
// it: the message says what went wrong, which callers may wrap or match on,
// and the hint says what to do, which is presentation. Folding them together
// is how errors end up with advice embedded in strings that other code then
// has to parse around.
type hintedError struct {
	err  error
	hint string
}

func (e *hintedError) Error() string { return e.err.Error() }
func (e *hintedError) Unwrap() error { return e.err }
func (e *hintedError) Hint() string  { return e.hint }

// withHint returns err carrying the action that resolves it.
//
// Only for cases where the right next step is genuinely known. A hint that
// guesses is worse than none: it trains people to ignore the ones that are
// right.
func withHint(err error, hint string) error {
	return &hintedError{err: err, hint: hint}
}

// hint prints a dimmed continuation of the line above it.
//
// Not a log line of its own. Muting means "extra detail about what you just
// read", and that only holds if the thing above it is the message it belongs
// to — a second level label would announce an independent event at a lower
// severity, which is the opposite of subordinate. So it carries no label and is
// indented to sit under the message it explains.
//
// Every call must follow a Warn or Error. A hint with nothing above it is
// muted text with no antecedent, which is just text nobody reads.
func (stdio *IO) hint(text string) {
	// Level labels are four columns plus a space, so this aligns with the
	// message text rather than the label.
	//
	// Decorated over the faint base rather than after it, so the names and
	// paths inside pick up their colour without breaking out of the muting —
	// they are still part of the secondary line, just the actionable part of it.
	_, _ = fmt.Fprintln(stdio.Err, "     "+stdio.decorate(stdio.styles().hint, text))
}

// reportWarnings prints the "looks sensitive, nothing redacts it" advisory.
//
// Names only — printing the value is the exact hazard being warned about.
//
// The names go in the message rather than in log fields, and the logger colours
// them from there. Fields would not work: charm log renders those as data,
// quoting anything containing control characters, so a coloured name arrives as
// var="\x1b[1mDB_PASSWORD\x1b[0m".
func reportWarnings(stdio *IO, l *logger, cfg *config.Config, findings []warn.Finding, strict bool) error {
	if len(findings) == 0 {
		return nil
	}

	names := make([]string, 0, len(findings))
	for _, f := range findings {
		names = append(names, f.Name)
	}

	l.Warn("you might leak sensitive values: " + strings.Join(names, ", "))
	stdio.hint(fmt.Sprintf(
		"add a redactions glob, or set `redact = false` on the variable to record that it is fine (%s)",
		cfg.Path))

	if strict {
		// Named rather than always blaming --strict: a run that fails without
		// anyone having passed a flag has to say what asked for the failure,
		// or it reads as pklenv deciding on its own.
		via := "--strict"
		if strictDefault() {
			via = strictEnv
		}
		return fmt.Errorf("%d unredacted sensitive-looking variable(s); %s treats this as an error", len(findings), via)
	}
	return nil
}

// maskForCI emits the masking directives of whichever CI system is running.
//
// This exists because redaction only covers output pklenv can see. Registering
// the values with the CI system extends the guarantee to logs pklenv is not in
// the path of — including the child process's own output when running --raw.
//
// GitHub's ::add-mask:: is the only widely-supported form; other systems either
// mask declared secrets automatically or offer nothing.
//
// Writes to the unmasked stream by necessity: the directive has to carry the
// literal value for the CI system to register it.
func (io *IO) maskForCI(values []string) {
	if os.Getenv("GITHUB_ACTIONS") != "true" {
		return
	}
	w := io.rawOut
	if w == nil {
		w = io.Out
	}
	for _, v := range values {
		if v == "" {
			continue
		}
		_, _ = fmt.Fprintf(w, "::add-mask::%s\n", v)
	}
}
