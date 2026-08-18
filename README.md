# pklenv

Typed, cascading environment config backed by [Pkl](https://pkl-lang.org).

`.pkl` files are the source of truth: they cascade via `amends`, they are typed,
they can reference each other, and they can `read("env:VAR")` to pull in values
assigned at runtime by CI/CD without those values ever touching disk.

Two subcommands over one evaluator:

```bash
pklenv run -- npm start        # inject the resolved values into a child process
pklenv emit                    # write flat .env files for tools that need one
```

## Install

```bash
go install github.com/idleberg/pklenv/cmd/pklenv@latest
```

> [!IMPORTANT]
> The [`pkl` CLI](https://pkl-lang.org/main/current/pkl-cli) has to be on `PATH`
> at runtime — `pklenv` evaluates by spawning `pkl server` and speaking its
> protocol. Install it however you manage tools; the
> [installation guide](https://pkl-lang.org/main/current/pkl-cli/index.html#installation)
> covers Homebrew, Mise, a JVM jar and native binaries.

## Configuring

File naming mirrors the dotenv convention:

| dotenv            | pklenv               |
| ----------------- | -------------------- |
| `.env`            | `env.pkl`            |
| `.env.local`      | `env.local.pkl`      |
| `.env.production` | `env.production.pkl` |

```pkl
amends "https://raw.githubusercontent.com/idleberg/pklenv/v0.1.0/pkl/PklEnv.pkl"

redactions { "*_TOKEN"; "*_SECRET" }

vars {
  ["NODE_ENV"] = "production"
  ["PORT"] = 8080
  ["API_TOKEN"] = read("env:CI_DEPLOY_TOKEN")
  ["LEGACY_KEY"] = new Var { value = "public"; redact = false }
}
```

> [!WARNING]
> Pin the schema to a tag rather than to `main`. The module is the contract a
> config is checked against, and an unpinned URL lets that contract move under a
> file that already validates.

Discovery and merging are separate mechanisms. Discovery is a plain glob —
`env.pkl` plus anything matching `env.*.pkl` — with no hierarchy inferred from
the filename. Merging happens only through a file's own explicit `amends`
declaration. `pklenv` never combines two files itself.

## Reading the environment

A config can pull values in during evaluation, which is how a CI-assigned secret
reaches a `.env` without ever being written down:

```pkl
vars {
  ["API_TOKEN"] = read("env:CI_DEPLOY_TOKEN")
}
```

There is no flag for this and no allowlist. Selection belongs in the config,
where Pkl already has a language for it — `read*` returns every match as a
`Mapping`, keyed with the `env:` prefix intact:

```pkl
vars {
  for (k, v in read*("env:APP_*")) {
    [k.drop(4)] = v
  }
}
```

`pklenv` previously gated each name behind an `--allow-env` grant. That was
removed because it guarded one of three doors: a config you do not trust can
equally `read("file:///…")` or execute code through a remote `package:` import,
so restricting the environment alone implied a protection it did not provide.
Sandboxing an untrusted config means restricting every resource kind and module
source at once, and that is not built. Until it is, the trust boundary is the
config file itself.

## Redaction

Output masking. Opt-in and explicit, following
[mise](https://mise.jdx.dev/environments/#redactions): nothing is masked unless
a glob matches or a `redact` flag says so. Values read from the environment are
**not** sensitive by default.

- `redactions { "*_TOKEN" }` — glob list, matched case-sensitively
- `new Var { value = "..."; redact = true }` — mask one the globs miss
- `new Var { value = "..."; redact = false }` — waive one they match too eagerly

Masking covers pklenv's own output _and_ the child's under `run`, which is why
the child's streams are piped. That costs the child its terminal; `--raw` hands
the streams over untouched and turns masking off, saying so as it does.

In GitHub Actions, `pklenv` also emits `::add-mask::` for every redacted value,
so the guarantee extends to logs it is not in the path of.

> [!CAUTION]
> Redaction is output masking, not access control. A masked value is still
> injected verbatim, and a child that writes it to a file or a network call is
> outside pklenv's reach.

Outside it too: a Pkl error raised _during_ evaluation — the failure is what
prevented pklenv from learning which values were secret. Those diagnostics are summarized unless you are at a terminal or
pass `--verbose`, so a CI log gets the classification without the excerpt.

## The unredacted-secret warning

Explicit-only redaction has one failure mode: forgetting. So `pklenv` warns when
a variable _name_ looks sensitive (`*SECRET*`, `*PASSWORD*`, `*TOKEN*`,
`*CREDENTIAL*`, `*PRIVATE_KEY*`, `*API_KEY*`, `*PASSWD*`) and no redaction rule
covers it.

```
WARN you might leak sensitive values: DB_PASSWORD
```

It prints names, never values — printing the value is the hazard being warned
about. It is advisory; `--strict` promotes it to a non-zero exit.

`PKLENV_STRICT=1` sets that default for every invocation, so a CI job declares
it once instead of repeating the flag; `--strict=false` still overrides it for a
single command. `1`, `true`, `yes` and `on` turn it on, `0`, `false`, `no` and
`off` turn it off, and anything else is treated as on with a warning naming the
value — a variable that exists to tighten a check must not loosen it on a typo.
It is a variable of its own rather than an inference from `CI`
on purpose — `--strict` is the one place a heuristic decides an exit code, and
the pattern list behind it will grow, so turning it on has to be somebody's
decision rather than a side effect of where the command ran.

The question it is really asking is whether anyone has decided about this
variable. There are three answers — the three states the code names `Redacted`,
`Waived` and `Undeclared` — and only the last one warns:

| is there a decision? | how it's spelled                   | masked | warns                            |
| -------------------- | ---------------------------------- | ------ | -------------------------------- |
| yes — it's a secret  | a glob matches, or `redact = true` | yes    | no                               |
| yes — it isn't       | `redact = false`                   | no     | no                               |
| no                   | nothing covers it                  | no     | yes, if the name looks sensitive |

`redact = false` is not the same as saying nothing. It records that somebody
looked, and that is the only difference the warning cares about — a waived
variable and an undeclared one are masked identically, which is to say not at
all. The same variable, two ways:

```pkl
["DB_PASSWORD"] = "hunter2000"                                     // warns
["DB_PASSWORD"] = new Var { value = "hunter2000"; redact = false } // silent
```

Both write `DB_PASSWORD=hunter2000` into the `.env`, and neither masks anything
in the output. `redact = false` answers the warning, not the masking.

Deliberately _not_ a bare `KEY` pattern: `SORT_KEY`, `PUBLIC_KEY` and
`KEYBOARD_SHORTCUTS` would all trip it, and a warning people learn to scroll
past takes the one that mattered down with it.

The heuristic never changes behaviour — not what resolves, not what is masked,
not what is written. It only ever prints.

## Development

```bash
mise install          # go, pkl, golangci-lint, hk
mise run test
mise run check        # everything the pre-commit hook runs
hk install            # formatting, linting and tests on commit
```

## License

Dual-licensed under either of

- Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE))
- MIT License ([LICENSE-MIT](LICENSE-MIT))

at your option. Unless you state otherwise, any contribution you intentionally
submit for inclusion in this work, as defined in the Apache-2.0 license, is
dual-licensed on these terms with no additional conditions.
