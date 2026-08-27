# Security

## Reporting

Email **contact@servor.app** with `[security]` in the subject.

Include what you found, how to reproduce it, and what you think it lets an
attacker do. If you would like a reply in French or English, say so.

Please give us a reasonable window to ship a fix before publishing. We will not
threaten you, and we will credit you unless you ask us not to.

## What is in scope

Anything that lets this agent execute a command without a valid signature,
accept a binary that was not signed by the embedded key, escape the user it is
configured to run as, or read something it should not.

## What is already known

These are documented in the README rather than hidden, and reporting them is not
a finding:

- The set of authorised signing keys is delivered by the control plane. The
  agent pins that signing is *required*, but a fully compromised control plane
  could add a key of its own.
- An interactive shell is signed once, at open. Subsequent keystrokes are not
  individually signed.
- Scheduled checks carry no grant; they are filtered by the local command
  blocklist only.
- The blocklist refuses destructive and lockout commands, not reads.
- The agent runs as the user it is configured with. Configure root and it is
  root.

Work that narrows any of these is very welcome.
