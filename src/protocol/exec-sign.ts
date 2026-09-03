// Vendored from packages/shared/src/crypto/exec-sign.ts — do not edit here.
//
// The agent ships as an independent, auditable artefact: a reader must be
// able to see every line that decides whether a command runs, without
// resolving a private Servor package. `bun run protocol:check` fails if this
// copy drifts from the original, because a guard that disagrees with the one
// on the control plane is worse than no guard.

import { ed25519 } from '@noble/curves/ed25519';
import { hkdf } from '@noble/hashes/hkdf';
import { sha256 } from '@noble/hashes/sha256';
import { wipe } from './wipe';

// ── End-to-end exec authorization signatures ────────────────────────────────
// An Ed25519 signing key is derived from the user's X25519 vault private key
// (high entropy → no pepper needed). The PRIVATE key never leaves the browser;
// only the PUBLIC key is provisioned to the agent at enrollment. Each exec/shell
// request is signed client-side and verified by the agent, so a compromised
// control plane (which never sees the vault key) cannot forge an execution.

const enc = new TextEncoder();
const EXEC_KDF_INFO = enc.encode('servor/exec-sign/v1');
const EXEC_DOMAIN = 'servor/exec-grant/v1';

/**
 * What the grant authorises.
 *
 * @remarks
 * `fs` covers the filesystem operations the browser drives (list, read, write,
 * move, remove…). Adding a member is backward compatible on purpose: the
 * domain string, the field order and the HKDF info are untouched, so every
 * signature already issued stays valid and no provisioned agent is invalidated.
 * For `fs` the `command` field carries the canonical descriptor built by
 * `describeFsOp` — which binds the CONTENT of a write, not just its path.
 *
 * `power` carries an **action name**, never a command line. That is the whole
 * reason it exists as its own kind: rebooting a machine is refused by the
 * shared blocklist, and the wrong way to allow it would be to punch a hole in
 * that list — which would also open it for the AI and the free terminal, where
 * the guard matters most. Instead the browser signs `reboot` or `poweroff`, the
 * agent maps that word to a command it holds itself, and no attacker-influenced
 * string ever reaches a shell on this path.
 *
 * `net` is one HTTP request made from inside the machine, to a service that
 * only listens there. Its `command` carries the descriptor built by
 * `describeLocalRequest` — method, host, port, path, headers and the HASH of
 * the body — so an approval for `GET /metrics` cannot be replayed as a
 * `DELETE`, and no relay can keep the signature while changing what is sent.
 */
export type ExecGrantKind = 'exec' | 'shell' | 'fs' | 'power' | 'net';

export type ExecGrant = {
  serverId: string;
  kind: ExecGrantKind;
  command: string; // '' for a shell-open grant
  nonce: string;
  ts: string; // unix seconds, as string
};

// Deterministic Ed25519 seed from the vault private key. Same vault key → same
// signing identity (so any unlocked session reproduces it; nothing to store).
const deriveExecSeed = (vaultPrivkey: Uint8Array): Uint8Array =>
  hkdf(sha256, vaultPrivkey, new Uint8Array(0), EXEC_KDF_INFO, 32);

/**
 * The exec-signing seed on its own — the ONLY material a client needs to sign
 * grants after the initial unlock. Unlike the X25519 vault private key it is
 * derived from, this seed cannot unwrap DEKs or decrypt any credential; it only
 * signs exec grants. Callers own the returned buffer and must wipe it.
 */
export const execSeedFromVault = (vaultPrivkey: Uint8Array): Uint8Array =>
  deriveExecSeed(vaultPrivkey);

const u32 = (n: number): Uint8Array => {
  const b = new Uint8Array(4);
  new DataView(b.buffer).setUint32(0, n, false);
  return b;
};

// Unambiguous length-prefixed framing so no field boundary can be forged by
// shifting content between fields (e.g. a command containing separators).
const canonicalExecMessage = (g: ExecGrant): Uint8Array => {
  const parts: Uint8Array[] = [enc.encode(EXEC_DOMAIN)];
  for (const field of [g.serverId, g.kind, g.command, g.nonce, g.ts]) {
    const bytes = enc.encode(field);
    parts.push(u32(bytes.length), bytes);
  }
  let total = 0;
  for (const p of parts) total += p.length;
  const out = new Uint8Array(total);
  let off = 0;
  for (const p of parts) {
    out.set(p, off);
    off += p.length;
  }
  return out;
};

/** Public signing key to provision to the agent at enrollment. */
export const execPublicKeyFromVault = (vaultPrivkey: Uint8Array): Uint8Array => {
  const seed = deriveExecSeed(vaultPrivkey);
  try {
    return ed25519.getPublicKey(seed);
  } finally {
    wipe(seed);
  }
};

/**
 * Sign an exec/shell grant with a pre-derived exec seed (see
 * {@link execSeedFromVault}). Does NOT wipe the seed — the caller keeps it for
 * the session.
 */
export const signWithExecSeed = (seed: Uint8Array, grant: ExecGrant): Uint8Array =>
  ed25519.sign(canonicalExecMessage(grant), seed);

/** Sign an exec/shell grant with the vault-derived key (browser-side). */
export const signExecGrant = (vaultPrivkey: Uint8Array, grant: ExecGrant): Uint8Array => {
  const seed = deriveExecSeed(vaultPrivkey);
  try {
    return signWithExecSeed(seed, grant);
  } finally {
    wipe(seed);
  }
};

/** Verify a grant signature against the provisioned public key (agent-side). */
export const verifyExecGrant = (
  execPubkey: Uint8Array,
  grant: ExecGrant,
  signature: Uint8Array,
): boolean => {
  try {
    return ed25519.verify(signature, canonicalExecMessage(grant), execPubkey);
  } catch {
    return false;
  }
};
