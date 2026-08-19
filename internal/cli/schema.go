package cli

import (
	"errors"
	"fmt"
	"path/filepath"
	"sync"

	"github.com/idleberg/pklenv/internal/schema"
)

// ensuredDirs remembers the directories already checked in this process.
//
// `emit` walks every discovered config, and in the ordinary case they share a
// directory — without this, a run over five configs would hash and possibly
// rewrite the same file five times, and report it five times too.
var ensuredDirs sync.Map

// ensureSchema puts a current copy of the PklEnv module beside a config.
//
// Called before evaluation, because the config amends the file this writes.
func ensureSchema(stdio *IO, configPath string, verbose bool) error {
	dir := filepath.Dir(configPath)

	// Keyed by the absolute path. A relative config resolves to ".", which is
	// the same string in every directory pklenv is ever run from — enough to
	// make the second directory in a process silently inherit the first one's
	// answer.
	key := dir
	if abs, err := filepath.Abs(dir); err == nil {
		key = abs
	}
	if _, seen := ensuredDirs.LoadOrStore(key, struct{}{}); seen {
		return nil
	}

	outcome, err := schema.Ensure(configPath)
	if err != nil {
		if errors.Is(err, schema.ErrForeign) {
			return withHint(err,
				fmt.Sprintf("pklenv rewrites %s automatically; move your own file aside, or rename it",
					schema.Filename))
		}
		return withHint(err,
			fmt.Sprintf("pklenv needs to write %s next to the config; make the directory writable, or commit the file",
				schema.Filename))
	}

	log := stdio.newLogger(verbose)
	switch outcome {
	case schema.Written:
		log.Info("wrote " + filepath.Join(dir, schema.Filename))
	case schema.Refreshed:
		// Announced rather than done quietly: it leaves the working tree dirty,
		// and an unexplained modified file is worse than a line of output.
		log.Warn(schema.Filename + " was out of date and has been regenerated; commit the change")
	case schema.Stale:
		log.Warn(schema.Filename + " is out of date and the directory is not writable; evaluating with the existing copy")
	case schema.Unchanged:
	}
	return nil
}
