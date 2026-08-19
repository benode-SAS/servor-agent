# Servor Agent

This is the program Servor asks you to install on your servers. It is published
in full so you can read what it does before you run it, and check that the
binary you were given was built from this source.

Installing an agent means giving a company the ability to run commands as root
on your machines. That deserves more than a promise, so: about 1,400 lines,
three dependencies, one file per concern. It is meant to be read in an
afternoon, and this document is written for someone who has not decided yet.

| | |
| --- | --- |
| **Runtime** | Bun, compiled to a single self-contained binary |
| **Dependencies** | `@noble/curves`, `@noble/hashes`, `shell-quote` |
| **Targets** | Linux x64/arm64 (glibc and musl), macOS x64/arm64, Windows x64 |
| **Network** | Outbound only — no listening port |
| **Licence** | Apache-2.0 |

---

## What it does

- **Dials out and stays connected.** A WebSocket to the control plane, opened
  from your machine. It listens on nothing and accepts no inbound connection,
  which is why it works behind NAT, a corporate firewall, or a network only
  reachable through a VPN.
- **Reports metrics** on an interval you set: CPU overall and per core, load,
  memory and swap, disks per mount point, network, uptime, processes.
- **Runs the checks it is told to run** — HTTP, TCP, SSL certificate expiry,
  SSH, disk space, process presence, and custom scripts — and reports the
  results. The TCP and TLS probes are pinned to `127.0.0.1`; an HTTP check dials
  the URL its definition names, which is the point of it: reaching a service the
  outside world cannot.
- **Executes commands, but only signed ones.** See below; this is the part
  worth reading.
- **Updates itself**, and only from a binary carrying a valid signature from a
  key compiled into it.

## What it does not do

Every security document lists strengths. The useful half is this one.

- **It does not verify *who* asked.** It verifies that a command was signed by a
  key its operator authorised. Whether that person was coerced, or their browser
  compromised, is outside what this program can see.
- **The list of authorised keys comes from the control plane.** That signing is
  required is a constant in the source, not a setting — the control plane cannot
  turn it off. But it does supply the key set, so a fully compromised one could
  add a key of its own. Closing that needs the keys pinned at enrolment, which is
  not implemented.
- **An interactive shell is signed once, at open.** The grant covers opening the
  session; the keystrokes after it are not individually signed. That is inherent
  to a PTY, and it means the relay sits inside the trust boundary for as long as
  the session lives.
- **Scheduled checks carry no grant.** A check definition arrives over the
  config channel. The command blocklist is applied to it locally, which is a
  guard, not a proof. An HTTP check also dials whatever URL it is given, so the
  config channel can make this agent issue outbound requests from inside your
  network — that is the feature, and it is also its cost.
- **The blocklist stops destruction, not disclosure.** It refuses `rm -rf /` and
  an overwrite of `/etc/shadow`. It will not stop a command from *reading* a
  file the agent's user can read.
- **It runs as the user you configure.** Configure root, and it is root.

If you find something that belongs on this list and is not on it, that is a
security report — see [SECURITY.md](SECURITY.md).

## How a command is authorised

The property worth having is that **the server you are trusting with your fleet
cannot execute on it**. Here is the mechanism, so you can judge whether it holds.

An Ed25519 signing key is derived from the operator's vault private key, which
is unwrapped in their browser and never sent anywhere. Only the public half ever
reaches this agent. Every execution request is signed in that browser, relayed
untouched by the control plane, and verified here — on your machine — before
anything runs.

```
browser                        control plane                  your server
  │                                  │                             │
  ├─ sign(serverId, kind,            │                             │
  │       command, nonce, ts) ──────►│── relayed verbatim ────────►│
  │                                  │                             ├─ verify signature
  │                                  │                             ├─ check nonce unseen
  │                                  │                             ├─ check timestamp
  │                                  │                             └─ run, or refuse
```

Verification lives in [`src/tunnel.ts`](src/tunnel.ts); the signature format is
in [`src/protocol/exec-sign.ts`](src/protocol/exec-sign.ts). The signed payload
is length-prefixed field by field, so two different grants cannot produce the
same bytes to sign.

Three things to check for yourself:

1. **It fails closed.** With no authorised key, execution is refused. There is
   no branch that runs a command when verification fails, and no setting that
   turns verification off.
2. **Replay is bounded.** A nonce table plus a timestamp window; the nonce is
   remembered for longer than a signature can remain valid, so a grant cannot
   come back once forgotten.
3. **The relay cannot rewrite what it relays.** The command that is verified is
   the command that runs — nothing is prefixed to it server-side, because a
   `cd` or a `sudo` added in transit would no longer be covered by the
   signature.

## Checking the binary you are running

Two independent methods, because they fail in different ways.

**Provenance** — every released binary carries a signed attestation binding its
digest to this repository, the commit it was built from, and the workflow that
built it:

```sh
gh attestation verify servor-agent-linux-x64 --repo benode-SAS/servor-agent
```

This works from any machine and is the quickest way to confirm origin.

**Rebuild it** — `bun build --compile` is deterministic here. Two independent CI
runs of the same commit produce byte-identical binaries, and the checkout path
does not affect the result. Both were measured rather than assumed.

```sh
bun install --frozen-lockfile && bun run build
sha256sum dist/servor-agent-linux-x64     # compare with SHA256SUMS in the release
```

**The caveat, stated plainly:** the digest is stable per builder platform, not
across them. The same source compiled on Windows and on Linux produces different
bytes. A rebuild therefore reproduces the published hash only on **Linux x64
with the pinned Bun version** — which is what the release workflow uses, and
what builds the binaries the API serves. Elsewhere your rebuild will run
correctly and hash differently; use the attestation there.

## Auto-update

A new build is installed only when its SHA-256 matches the manifest **and** that
hash carries a valid Ed25519 signature from the key in
[`src/pubkey.ts`](src/pubkey.ts).

The checksum alone would not be enough: it is served by the same host as the
binary, so it proves the download was not corrupted in transit and nothing about
who produced it. Built without a public key, the agent refuses to update at all
rather than installing something it cannot verify.

Updates are applied when the agent is idle — never in the middle of a command or
an open terminal.

## Configuration

A single JSON file, `0600`, read at startup:

| Platform | Path |
| --- | --- |
| Linux, macOS | `/etc/servor-agent/config.json` |
| Windows | `%ProgramData%\ServorAgent\config.json` |

Override with `SERVOR_CONFIG`.

```json
{
  "serverId": "uuid of this server",
  "secret": "per-server HMAC secret, issued at enrolment",
  "apiUrl": "https://api.servor.benode.fr",
  "intervalSeconds": 60,
  "mode": "tunnel",
  "user": "deploy"
}
```

`intervalSeconds` is clamped to 15–300. `mode` is `push` for metrics only, or
`tunnel` to also accept signed commands. `user` is the OS account commands run
as — omit it and they run as the agent's own user.

## Layout

| File | Responsibility |
| --- | --- |
| `src/index.ts` | startup, the metric and config loops, lifecycle |
| `src/tunnel.ts` | the outbound WebSocket, grant verification, shells |
| `src/checks.ts` | the check types and how each is executed |
| `src/metrics.ts` | reading the system |
| `src/config.ts` | loading and atomically saving the config file |
| `src/updater.ts` | download, checksum, signature, swap |
| `src/protocol/` | copied from the control plane — see below |

`src/protocol/` holds the four files that decide whether a command runs. They
also exist in Servor's own codebase, and are copied here rather than imported so
that reading them does not require access to a private package. `bun run
protocol:check` fails if the copies drift: a guard on your machine that
disagrees with the guard on the server is worse than no guard at all.

## Building

```sh
bun install
bun run typecheck
bun run protocol:check
bun run build          # all seven targets into dist/
```

## Contributing

Patches are welcome, particularly on the parts that decide whether a command
runs. Read [CONTRIBUTING.md](CONTRIBUTING.md) first — this repository is a
mirror, and that changes how changes flow.

Found a way to make this agent execute something it should not?
[SECURITY.md](SECURITY.md), not a pull request.

## Licence

Apache-2.0. Copyright BENODE SAS.
