<div align="center">

<picture>
  <source media="(prefers-color-scheme: dark)" srcset=".github/assets/logo-dark.svg">
  <img src=".github/assets/logo-light.svg" alt="Servor" width="240">
</picture>

<br><br>

**The Servor agent** — supervision and command execution for the servers you
already run.

<br>

[![Build](https://github.com/benode-SAS/servor-agent/actions/workflows/build.yml/badge.svg)](https://github.com/benode-SAS/servor-agent/actions/workflows/build.yml)
[![Release](https://img.shields.io/github/v/release/benode-SAS/servor-agent?label=release&color=06b6d4)](https://github.com/benode-SAS/servor-agent/releases/latest)
[![Licence](https://img.shields.io/badge/licence-Apache--2.0-8b5cf6)](LICENSE)
[![Bun](https://img.shields.io/badge/bun-1.3-black)](https://bun.sh)

</div>

---

A single compiled binary that connects out to [Servor](https://servor.benode.fr),
reports what the machine is doing, runs the checks you configured, and executes
the commands you approve. No port to open, no runtime to install.

```
┌─ your server ──────────────┐            ┌─ Servor ─────────┐
│  servor-agent ─────────────┼── wss ────►│  control plane   │
│    metrics, checks, exec   │  outbound  │                  │
└────────────────────────────┘            └──────────────────┘
```

## Install

The agent is installed for you when you add a server in Servor. By hand: take
the binary for your platform from the
[latest release](https://github.com/benode-SAS/servor-agent/releases/latest),
put it on `PATH`, write the config file below, run it under systemd.

## Configuration

One JSON file, mode `0600`:

| Platform | Path |
| --- | --- |
| Linux, macOS | `/etc/servor-agent/config.json` |
| Windows | `%ProgramData%\ServorAgent\config.json` |

```json
{
  "serverId": "uuid of this server",
  "secret": "issued when the server is enrolled",
  "apiUrl": "https://api.servor.benode.fr",
  "intervalSeconds": 60,
  "mode": "tunnel",
  "user": "deploy"
}
```

| Field | |
| --- | --- |
| `intervalSeconds` | delay between metric pushes, clamped to 15–300 |
| `mode` | `push` for metrics only, `tunnel` to also accept commands |
| `user` | OS account commands run as; omit to run as the agent's own user |

Set `SERVOR_CONFIG` to load the file from elsewhere.

## What it collects

CPU overall and per core, load average, memory and swap, disks per mount point,
network counters, uptime, process count — every `intervalSeconds`.

Checks are configured in Servor and run from here: HTTP, TCP, SSL certificate
expiry, SSH, disk space, process presence, custom scripts. TCP and TLS probes
are pinned to `127.0.0.1`; an HTTP check dials the URL you give it, which is the
point — reaching a service that is not exposed publicly.

## Execution

Commands are signed in the browser by the operator who issued them, relayed
untouched by Servor, and verified here before anything runs. The signing key is
derived from a vault key that never leaves that browser, so the control plane
carries grants it cannot forge.

[`src/tunnel.ts`](src/tunnel.ts) checks the signature against the public keys it
was given, that the grant names this server, that the timestamp is inside a
window, and that the nonce is unused. Any of those failing means the command
does not run; with no key present, nothing runs.

Two things worth knowing up front:

- A terminal session is signed when it opens, not per keystroke — a PTY cannot
  work otherwise.
- Scheduled checks arrive over the config channel and carry no signature. The
  ones that run a shell go through the blocklist in
  [`src/protocol/command-guards.ts`](src/protocol/command-guards.ts), which
  refuses destructive and lockout commands.

### The tunnel is transport, not trust

The connection is a plain `wss://` with the standard certificate validation your
runtime does — no pinning, no mTLS, nothing exotic. The handshake is an HMAC
proving which agent is speaking; it authorises nothing.

That is deliberate, and it is the part worth checking if you are deciding
whether to run this. Authority lives in the per-command signature, verified on
your machine against a key that never left the operator's browser. Break the
TLS, take over the control plane, sit in the middle — you get the ability to
*relay*, not to *forge*. There is no command you can inject that the agent will
accept.

What that does not cover: without pinning, a compromised CA or a corporate proxy
terminating TLS can read the stream, and since a shell session is signed only at
open, whoever holds the pipe can read that session. Replay is bounded by the
nonce and timestamp checks, not by the transport.

## Updates

The agent replaces itself when Servor advertises a newer build, if the download
matches the expected SHA-256 **and** that hash carries a valid Ed25519 signature
from the key in [`src/pubkey.ts`](src/pubkey.ts). Built without a public key, it
does not self-update.

Swaps happen when the agent is idle, never during a command or an open terminal.

## Verifying a binary

Releases ship `SHA256SUMS` and a signed provenance attestation:

```sh
sha256sum servor-agent-linux-x64
gh attestation verify servor-agent-linux-x64 --repo benode-SAS/servor-agent
```

You can also rebuild it: `bun build --compile` is deterministic, so on Linux x64
with the pinned Bun version you get the same bytes as the release. Other builder
platforms produce a working binary with a different hash.

## Building

```sh
bun install
bun run typecheck
bun run protocol:check    # vendored files still match their source
bun test                  # unit suite
bun run build             # all seven targets into dist/
```

Targets: Linux x64/arm64 (glibc and musl), macOS x64/arm64, Windows x64.

The tests run on Linux and Windows in CI. The ones worth reading first are in
[`src/grant.test.ts`](src/grant.test.ts): replay, a grant minted for another
server, an `exec` grant reused to open a shell, timestamps either side of the
acceptance window, and what happens with no authorized key — the properties the
section above claims, written down as assertions.

## Layout

| | |
| --- | --- |
| `src/index.ts` | startup, metric and config loops |
| `src/tunnel.ts` | outbound WebSocket, grant verification, shells |
| `src/checks.ts` | the check types and how each runs |
| `src/metrics.ts` | reading the system |
| `src/config.ts` | loading and saving the config file |
| `src/updater.ts` | download, verify, swap |
| `src/protocol/` | shared with the control plane, copied in |

`src/protocol/` holds four files that also live in Servor's own codebase, copied
here so that reading this repository does not require a private package.
`bun run protocol:check` fails if the copies drift.

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) — this repository is a mirror, which
changes how patches flow. Security reports go to [SECURITY.md](SECURITY.md).

## Licence

Apache-2.0 — Copyright BENODE SAS.
