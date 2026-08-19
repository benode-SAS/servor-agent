# Servor Agent

The program Servor asks you to install on your servers. It is published in full
so you can read exactly what it does before you run it, and check that the
binary you downloaded was built from this source.

Around 1,400 lines, three dependencies. It is meant to be read in an afternoon.

## What it does

- Opens an **outbound** WebSocket to the control plane and keeps it alive. It
  listens on no port and accepts no inbound connection, which is why it works
  behind NAT, a corporate firewall or a VPN-only network.
- Pushes metrics on an interval: CPU overall and per core, load, memory and
  swap, disks per mount point, network, uptime, processes.
- Runs the checks it is told to run and reports their results.
- Executes commands **only when they carry a valid signature** (see below).
- Updates itself, only from a binary signed with a key embedded at build time.

## What it does not do

Stated plainly, because a security document that only lists strengths is not
worth reading:

- **It does not verify who asked.** It verifies that a command was signed by a
  key its operator authorised. It cannot tell you whether that person was
  coerced, or whether their browser was compromised.
- **The list of authorised keys arrives from the control plane.** The agent
  pins that signing is *required* — that is compiled in, not configurable
  remotely — but a control plane that is fully compromised could add a key of
  its own to the authorised set. Closing that requires pinning the key set at
  enrolment, which is not implemented today.
- **A shell session is signed once, at open.** The grant covers opening the
  shell; the keystrokes that follow are not individually signed. This is
  inherent to an interactive terminal, and it means the relay sits inside the
  trust boundary for the lifetime of a session.
- **Scheduled checks are not signed.** A check definition arrives over the
  config channel and carries no grant. The command blocklist is applied to it
  locally (`src/protocol/command-guards.ts`), which is a guard, not a proof.
- **The blocklist refuses destructive and lockout commands, not reads.** It
  will stop `rm -rf /` and an overwrite of `/etc/shadow`. It will not stop a
  command from reading a file the agent's user can read.
- **It runs as the user you configure.** If you configure root, it is root.

## The signature, concretely

An Ed25519 signing key is derived from the operator's vault private key, which
never leaves their browser. Only the public half reaches this agent. Every
execution request is signed in the browser and verified here, on your machine,
before anything runs — so the control plane relays a grant it cannot forge.

Verification is in [`src/protocol/exec-sign.ts`](src/protocol/exec-sign.ts).
The signed payload is length-prefixed field by field, so no two different
grants can produce the same bytes. Replay is refused by a nonce table plus a
timestamp window, both in [`src/tunnel.ts`](src/tunnel.ts).

If no authorised key is present, execution is refused. There is no path in this
code that runs a command when verification fails.

## Auto-update

The agent downloads a new build only if its SHA-256 matches the manifest **and**
that hash carries a valid Ed25519 signature from the key embedded in
[`src/pubkey.ts`](src/pubkey.ts). A checksum served by the same host as the
binary proves the download was not corrupted; it proves nothing about who
produced it, which is why the signature is mandatory.

Build without a public key and the agent refuses to update at all, rather than
installing something it cannot verify.

## Vendored code

`src/protocol/` holds the four files that decide whether a command runs. They
originate in Servor's shared package and are copied here on purpose: reading
them must not require access to a private package. `bun run protocol:check`
verifies the copies still match their source, and fails the build if they drift
— a guard that disagrees with the one on the control plane is worse than no
guard.

## Build

```sh
bun install
bun run typecheck
bun run protocol:check
bun run build            # all seven targets
```

Targets: Linux x64/arm64 (glibc and musl), macOS x64/arm64, Windows x64.

## Licence

Apache-2.0.
