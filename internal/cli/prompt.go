package cli

import (
	"errors"
	"io"
	"os"

	"github.com/charmbracelet/huh"
)

// errDeclined reports that the user answered no, or walked away from the
// question with Ctrl-C or Esc.
//
// Aborting and answering no are folded together on purpose: at a destructive
// prompt they mean the same thing, and the only reading of an abort that does
// not risk the file is the conservative one.
var errDeclined = errors.New("declined")

// form runs a huh form against explicit streams.
//
// The streams are the caller's business, and both defaults are wrong here. huh
// reaches for os.Stdin/os.Stdout on its own; pklenv reads from the cobra
// command's input, so tests can drive it, and writes to the *unmasked* stderr,
// because the masker buffers by line and a form redraws in place without ever
// emitting one — a masked form would sit in the buffer, invisible, while the
// read blocks.
//
// Help is suppressed. huh's key hints are for multi-field forms with tab
// traversal; pklenv only ever asks one thing at a time, and the footer is
// noise on a prompt with two answers.
func (stdio *IO) form(in io.Reader, out io.Writer, field huh.Field) error {
	err := huh.NewForm(huh.NewGroup(field)).
		WithTheme(huh.ThemeCharm()).
		WithInput(in).
		WithOutput(out).
		WithShowHelp(false).
		Run()

	switch {
	case err == nil:
		return nil
	case errors.Is(err, huh.ErrUserAborted):
		return errDeclined
	default:
		return err
	}
}

// confirm asks a yes/no question and reports the answer.
//
// Inline, so the question and its two answers occupy one line — this replaces a
// [y/N] prompt, and growing it into a three-line block to ask the same thing
// would be a downgrade.
func (stdio *IO) confirm(in io.Reader, out io.Writer, title, yes, no string) (bool, error) {
	var ok bool
	err := stdio.form(in, out, huh.NewConfirm().
		Title(title).
		Affirmative(yes).
		Negative(no).
		Inline(true).
		Value(&ok))
	if err != nil {
		return false, err
	}
	return ok, nil
}

// pick asks the user to check off a subset of options.
//
// Nothing is preselected. The list is the one destructive step's input, and a
// preselected list turns a stray Enter into "write all of them" — the answer
// the user opened the picker to avoid.
func (stdio *IO) pick(in io.Reader, out io.Writer, title string, labels []string) ([]int, error) {
	opts := make([]huh.Option[int], len(labels))
	for i, label := range labels {
		opts[i] = huh.NewOption(label, i)
	}

	var chosen []int
	if err := stdio.form(in, out, huh.NewMultiSelect[int]().
		Title(title).
		Options(opts...).
		Value(&chosen)); err != nil {
		return nil, err
	}
	return chosen, nil
}

// canPrompt reports whether there is a terminal to run a form on.
//
// Both streams matter, for different reasons: without a terminal on stdin there
// is nobody to answer, and without one on stderr the form has nowhere to draw.
// A form given neither does not fail loudly — it renders into a pipe and waits
// forever, which is the shape of a hung CI job.
func (stdio *IO) canPrompt() bool {
	return isTerminal(os.Stdin) && stdio.ErrIsTerminal()
}
