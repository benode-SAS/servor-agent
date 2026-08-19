# Contributing

Issues and pull requests are welcome.

## Before opening a pull request

```sh
bun install
bun run typecheck
bun run protocol:check
bun run build
```

CI runs the same, plus a compile of every target.

## Two things specific to this repository

**`src/protocol/` is copied, not authored here.** Those four files also exist in
Servor's control plane and the two copies have to stay identical, so changing
them here alone will fail `protocol:check`. Open an issue instead and the change
gets made at the source and mirrored back.

**Execution requires a verified signature.** There is no code path that runs a
command when verification fails, and adding one would defeat the point of the
design — so a patch introducing a bypass, however convenient, will be declined.

## How changes flow

The canonical history lives in Servor's monorepo; this repository is a mirror.
Merged pull requests here are carried upstream by hand, which is slower than a
normal fork workflow — worth knowing before you start something large.

## Style

Biome, TypeScript strict. Comments explain why, not what.

## Security

Found something exploitable? [SECURITY.md](SECURITY.md), not a pull request.
