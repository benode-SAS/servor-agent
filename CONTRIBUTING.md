# Contributing

Patches are welcome, particularly on the parts that decide whether a command
runs. If you find a way to make this agent execute something it should not,
please read `SECURITY.md` first — that is a disclosure, not a pull request.

## Before you open a pull request

```sh
bun install
bun run typecheck
bun run protocol:check
bun run build
```

All four must pass. CI runs the same, plus a compile of every target.

## Two rules that are not style preferences

**`src/protocol/` is copied, not authored here.** Those four files also exist in
Servor's control plane, and the two copies must agree — a guard on your machine
that disagrees with the guard on the server is worse than no guard. Changing
them here alone will fail `protocol:check`. Open an issue instead and the change
will be made at the source and mirrored.

**Nothing may execute without a verified grant.** There is deliberately no code
path that runs a command when signature verification fails, and no configuration
that disables it. A patch adding one will be declined regardless of how
convenient the use case is.

## Where this code lives

The canonical history is in Servor's monorepo; this repository is a mirror,
published so the agent can be read and rebuilt by the people who run it. Merged
pull requests here are pulled back upstream by hand. That is slower than a
normal fork workflow, and it is the honest description of how it works.

## Style

Biome, tabs as configured, TypeScript strict. Comments explain why, not what.
