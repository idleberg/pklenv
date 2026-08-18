# Playground

Manual smoke tests against the fixtures in this directory. Not part of the test
suite — the automated coverage lives in `internal/cli/cli_test.go`; this is for
poking at the CLI by hand.

**These fixtures write `.env*` files into this directory.** They are gitignored;
`rm -f .env*` when you're done.

## The fixtures

Working configs:

| File                 | What it exercises                                                                            | Emits to          |
| -------------------- | -------------------------------------------------------------------------------------------- | ----------------- |
| `env.pkl`            | the whole schema: scalars, coercion, `redactions` globs, per-var `redact` in both directions | `.env`            |
| `env.production.pkl` | `amends "env.pkl"` — cascading, and the one place merging happens                            | `.env.production` |
| `env.bulkread.pkl`   | `read*("env:PKLENV_BULK_*")` bulk selection                                                  | `.env.bulkread`   |
| `env.secretread.pkl` | `read("env:NAME")` for a value the environment must supply                                   | `.env.secretread` |
| `env.warn.pkl`       | a sensitive-looking name that nothing redacts — the only fixture that trips the warning      | `.env.warn`       |

Configs that fail on purpose, one per error class:

| File                | Fails with                                                            |
| ------------------- | --------------------------------------------------------------------- |
| `env.badamends.pkl` | `Cannot find module` — the amends path resolves relative to the file  |
| `env.badprop.pkl`   | `Cannot find property` — `redaction`, not `redactions`                |
| `env.badname.pkl`   | the schema's `EnvName` constraint — a key a `.env` cannot round-trip  |
| `env.unset.pkl`     | `Cannot find resource` — `read()` of a variable that is not set       |
| `env.badglob.pkl`   | pklenv's own glob validation, _after_ a successful evaluation         |
| `notenv.pkl`        | not a pklenv config at all; discovery skips it, naming it is an error |

Because five fixtures fail deliberately, a bare `pklenv emit` in this directory
always ends in an error — it stops at `env.badamends.pkl`, the first one
alphabetically. Name a config explicitly, or use `-i`, to work with the rest.

## emit

| Command                                     | Expect                                                                            |
| ------------------------------------------- | --------------------------------------------------------------------------------- |
| `pklenv emit env.pkl`                       | `INFO wrote .env vars=6 redacted=2`                                               |
| `pklenv emit env.pkl` (again)               | confirm dialog: `.env exists. Overwrite?`, defaulting to `Keep`                   |
| `pklenv emit env.pkl --force`               | overwrites, no prompt                                                             |
| `pklenv emit env.pkl --force --outdir /tmp` | writes `/tmp/.env`, leaves this directory alone                                   |
| `pklenv emit env.production.pkl --force`    | `.env.production` carries `TIER=prod` **and** everything inherited from `env.pkl` |
| `pklenv emit -i`                            | checklist of all ten mappings, nothing preselected                                |
| `pklenv emit -i`, then Esc                  | `nothing selected; no files written`, exit 0                                      |

### Reading the environment

```sh
PKLENV_TEST_SECRET=hunter2 pklenv emit env.secretread.pkl --force
cat .env.secretread            # value present in the file...
                               # ...but masked in anything pklenv printed
```

```sh
PKLENV_BULK_ONE=1 PKLENV_BULK_TWO=2 pklenv emit env.bulkread.pkl --force
cat .env.bulkread              # PKLENV_BULK_ONE=1, PKLENV_BULK_TWO=2
```

`read*` keys its result by the full resource URI, so the config's `k.drop(4)`
strips the `env:` scheme, not the `PKLENV_BULK_` prefix. Unset variables simply
do not appear — no error, unlike `read()`.

### The sensitive-name warning

```sh
pklenv emit env.warn.pkl --force     # WARN you might leak sensitive values: DB_PASSWORD
pklenv emit env.warn.pkl --strict    # same warning, now fatal; nothing is written

PKLENV_STRICT=1 pklenv emit env.warn.pkl               # fatal too, and the error names PKLENV_STRICT
PKLENV_STRICT=1 pklenv emit env.warn.pkl --strict=false --force   # the flag wins; the file is written
```

Only `env.warn.pkl` trips it. Everywhere else a suspicious name is either
matched by a `redactions` glob or carries an explicit `redact`, which records a
decision rather than leaving one absent.

## run

| Command                                             | Expect                                                                       |
| --------------------------------------------------- | ---------------------------------------------------------------------------- |
| `pklenv run -f env.pkl -- env`                      | resolved vars in the child's environment; `API_TOKEN` masked in its output   |
| `pklenv run -f env.pkl -- printenv API_TOKEN`       | `[redacted]` — the child got the real value, pklenv masked it on the way out |
| `pklenv run -f env.pkl --raw -- printenv API_TOKEN` | a `WARN` about unmasked output, then the real token                          |
| `pklenv run -f env.pkl -- sh -c 'exit 7'`           | pklenv exits 7 — the child's status is mirrored, not reported                |
| `pklenv run -- true`                                | defaults to `env.pkl`                                                        |
| `pklenv run -f env.warn.pkl --strict -- true`       | the warning is fatal; the child never starts                                 |

## Error cases

Every one of these is reachable from the CLI. The second column is the message,
the third the hint printed under it (`—` where there isn't one worth guessing).

### Finding a config

| Command                              | Message                                                                          | Hint                                          |
| ------------------------------------ | -------------------------------------------------------------------------------- | --------------------------------------------- |
| `cd /tmp && pklenv emit`             | `no env*.pkl config found in this directory`                                     | `create env.pkl, or name a config explicitly` |
| `pklenv emit notenv.pkl`             | `not a pklenv config: expected env.pkl or env.<environment>.pkl`                 | —                                             |
| `pklenv emit missing.pkl`            | same _not a config_ error — the naming rule is checked before the file is opened | —                                             |
| `pklenv emit env.missing.pkl`        | `reading env.missing.pkl: … no such file or directory`                           | —                                             |
| `pklenv run -f env.nope.pkl -- true` | same, via `-f`                                                                   | —                                             |
| `env -i pklenv emit env.pkl`         | `the pkl CLI is required but was not found on PATH`                              | `install it however you manage tools; see …`  |

### Evaluating it

All four are Pkl's own diagnostics, summarized to the first line unless there is
a terminal or `--verbose` — the excerpt below the summary can quote values, and
that text cannot be masked, because the evaluation failed before pklenv learned
which values were secret.

| Command                         | Message                                                  | Hint                                                              |
| ------------------------------- | -------------------------------------------------------- | ----------------------------------------------------------------- |
| `pklenv emit env.badamends.pkl` | `Cannot find module …/nope/PklEnv.pkl`                   | the path resolves relative to the file, not the working directory |
| `pklenv emit env.badprop.pkl`   | `Cannot find property redaction in module pklenv.PklEnv` | check the name against the schema this config amends              |
| `pklenv emit env.unset.pkl`     | `Cannot find resource env:PKLENV_DEFINITELY_NOT_SET`     | use `read?("env:NAME")` for one that may be absent                |
| `pklenv emit env.badname.pkl`   | `Type constraint matches(Regex(…)) violated`             | names take letters, digits and underscores, not leading digits    |

Compare the two renderings — the split keys off the terminal, so a pipe shows
the CI shape:

```sh
pklenv emit env.unset.pkl               # summary + hint
pklenv emit env.unset.pkl --verbose     # full diagnostic, source excerpt and all
pklenv emit env.unset.pkl 2>&1 | cat    # what a CI log gets: summary only
```

A Pkl diagnostic with no matching hint falls back to
`run with --verbose for the full Pkl diagnostic, which may quote values` — but
only when it was summarized, since there is nothing to offer someone already
looking at the whole thing.

### After a successful evaluation

| Command                                                 | Message                                                                        | Hint                                        |
| ------------------------------------------------------- | ------------------------------------------------------------------------------ | ------------------------------------------- |
| `pklenv emit env.badglob.pkl`                           | `in env.badglob.pkl: invalid redaction pattern [: syntax error in pattern`     | what the glob syntax is                     |
| `pklenv emit env.warn.pkl --strict`                     | `1 unredacted sensitive-looking variable(s); --strict treats this as an error` | — (the warning above it carries the advice) |
| `pklenv emit env.pkl --force --outdir /nonexistent-dir` | `writing /nonexistent-dir/.env: … no such file or directory`                   | —                                           |

### Prompts

Both refuse rather than guess when there is no terminal. `</dev/null` is the
case to check with: a character device, but not a terminal, which is what a
naive `isatty` substitute gets wrong.

| Command                                                | Message                                                                   | Hint                           |
| ------------------------------------------------------ | ------------------------------------------------------------------------- | ------------------------------ |
| `pklenv emit env.pkl </dev/null` (with `.env` present) | `.env already exists and there is no terminal to confirm on`              | `pass --force to overwrite it` |
| `pklenv emit -i </dev/null`                            | `--interactive needs a terminal to show the list on`                      | drop it, or name a config      |
| `pklenv emit -i env.pkl`                               | `--interactive picks from the discovered configs, but a FILE was named`   | drop one or the other          |
| `pklenv emit env.pkl`, answer `Keep`                   | `declined overwriting .env`                                               | —                              |
| `pklenv emit env.pkl`, then Ctrl-C                     | same — aborting and declining mean the same thing at a destructive prompt | —                              |

### Running a child

| Command                                   | Message                                                       | Hint                                    |
| ----------------------------------------- | ------------------------------------------------------------- | --------------------------------------- |
| `pklenv run`                              | `run needs a command to execute`                              | `the command goes after a -- separator` |
| `pklenv run -f env.pkl -- nosuchbinary`   | `starting nosuchbinary: … executable file not found in $PATH` | —                                       |
| `pklenv run -f env.pkl -- sh -c 'exit 7'` | nothing printed — the exit status _is_ the report             | —                                       |

## CI masking

```sh
GITHUB_ACTIONS=true pklenv emit env.pkl --force
# ::add-mask::… lines on stdout, one per redacted value, carrying the literal
# value on purpose — that is what registers it with the runner
```

## Colouring

Variable names and file paths are coloured wherever they appear in a message,
including inside Pkl's diagnostics and inside muted hint lines. Worth an eye on
after touching `internal/cli/decorate.go`:

```sh
pklenv emit missing.pkl        # three paths in one sentence
pklenv emit env.unset.pkl -v   # paths and a variable name inside a source excerpt
pklenv emit env.warn.pkl       # a name in the warning, a path in the muted hint
```

## Cleanup

```sh
rm -f .env .env.*
```
