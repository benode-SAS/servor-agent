import { verifyExecGrant } from './protocol/exec-sign';

// End-to-end execution policy, synced from the control plane by fetchConfig.
// Every exec and shell.open must carry a grant signed by one of the authorized
// vault-derived operator keys, and that signature is verified HERE, on this
// host. The control plane never holds the private half, so it relays a grant it
// cannot forge; it decides what reaches the agent, not what the agent accepts.
//
// The initial value is deliberately the restrictive one: a command that arrives
// before the first config sync finds signing required and no key to satisfy it,
// so it is refused rather than run.
// Not a variable, and not settable from the network. The control plane used to
// send a `requireSignedExec` flag that this agent honoured; a response that
// merely *omitted* it turned verification off entirely, which made the one
// property the agent exists to provide remotely disableable — by silence.
const EXEC_REQUIRE = true;

/** How far in the past a grant's timestamp may sit and still be accepted. */
export const GRANT_PAST_SKEW_S = 300;
/** How far ahead a grant's timestamp may sit — tolerance for clock drift, no more. */
export const GRANT_FUTURE_SKEW_S = 60;
/**
 * How long an accepted nonce is remembered.
 *
 * @remarks
 * A grant is accepted anywhere in a window spanning both skews, so one
 * signature can remain cryptographically valid for their sum. The nonce has to
 * outlive that window, with margin — forget a nonce while its signature is
 * still inside the acceptance window and the same captured grant becomes
 * replayable. That is the entire reason this TTL exceeds the window rather than
 * matching it.
 */
export const NONCE_TTL_MS = (GRANT_PAST_SKEW_S + GRANT_FUTURE_SKEW_S + 60) * 1000;

const fromB64 = (s: string): Uint8Array => Uint8Array.from(Buffer.from(s, 'base64'));

/** Verifies grants for one enrolled server, holding that server's nonce table. */
export type GrantVerifier = {
  /**
   * Install the execution policy received from the control plane.
   *
   * @param keysB64 - Base64 Ed25519 public keys allowed to sign grants;
   * replaces the previous set, so revoking an operator is a matter of dropping
   * their key from the next config response.
   *
   * @remarks
   * Only public keys ever reach this agent. It can verify a grant and can do
   * nothing else with these bytes — it cannot mint one, and neither can
   * anything that reads them off this machine.
   */
  setKeys: (keysB64: string[]) => void;
  verify: (kind: 'exec' | 'shell', command: string, msg: Record<string, unknown>) => boolean;
};

/**
 * Build the grant verifier for this agent's own server identity.
 *
 * @param serverId - The agent's own id, taken from local config. Grants are
 * checked against it and never against anything the message claims.
 * @param now - Clock, injectable so the acceptance window can be exercised.
 */
export const createGrantVerifier = ({
  serverId,
  now = Date.now,
}: {
  serverId: string;
  now?: () => number;
}): GrantVerifier => {
  let execKeys: Uint8Array[] = [];
  /** Nonces of accepted grants, mapped to when they were accepted. */
  const seenNonces = new Map<string, number>();

  /**
   * Decide whether a request to run something carries a valid operator grant.
   *
   * @param kind - `exec` or `shell`; part of the signed message, so a grant for
   * a one-shot command cannot be re-used to open an interactive session.
   * @param command - The exact command about to run, also signed. Verifying the
   * string that executes, and not a description of it, is what stops the relay
   * from substituting a different command behind a valid signature.
   * @param msg - Raw tunnel message; `nonce`, `ts` and `sig` are read from it
   * and everything else ignored.
   * @returns `true` only when a signature over the whole grant verifies against
   * one of the authorized keys. Every other outcome is `false`, and the caller
   * refuses to run anything.
   *
   * @remarks
   * This function is the trust boundary. Nothing upstream of it is trusted: the
   * control plane relays a grant, it does not vouch for one.
   *
   * Four independent conditions must hold, and each closes a distinct attack.
   *
   * - **A key must exist.** With no authorized key, no signature can verify and
   *   the answer is `false`. Verification fails closed on purpose: an agent that
   *   ran commands while it had nothing to check them against would be at the
   *   mercy of whoever spoke to it first.
   * - **The grant is bound to this server.** `serverId` is the agent's own, taken
   *   from local config and never from the message, so a grant captured on one
   *   host cannot be replayed against another.
   * - **The timestamp must fall inside the acceptance window.** The window is
   *   asymmetric by design: several minutes of lateness are tolerated because
   *   networks and queues are slow, but a grant minted far in the future is
   *   refused — accepting one would stretch its validity past the lifetime of
   *   the nonce that is supposed to make it single-use.
   * - **The nonce must be unseen.** Signatures are replayable by anyone who
   *   observes one; the nonce table is what makes a grant good exactly once.
   *   It is only recorded on success, so a rejected grant cannot be used to
   *   consume a nonce someone else would legitimately have presented.
   *
   * The table is pruned on every acceptance rather than past some size
   * threshold: an earlier version pruned only after a thousand entries, which
   * let expired nonces sit in memory while fresh ones were still being refused.
   * The map stays small, so the sweep costs nothing.
   *
   * What this does not establish is who was at the keyboard. It proves a
   * request was signed by a key the operator authorized — not that the person
   * holding it meant to send this command, or that their browser was not
   * compromised.
   */
  const verify = (
    kind: 'exec' | 'shell',
    command: string,
    msg: Record<string, unknown>,
  ): boolean => {
    if (!EXEC_REQUIRE) return true;
    const nonce = String(msg.nonce ?? '');
    const ts = String(msg.ts ?? '');
    const sig = String(msg.sig ?? '');
    if (!nonce || !ts || !sig || execKeys.length === 0) return false;
    const tsn = Number.parseInt(ts, 10);
    const ageS = Math.floor(now() / 1000) - tsn;
    if (!Number.isFinite(tsn) || ageS > GRANT_PAST_SKEW_S || ageS < -GRANT_FUTURE_SKEW_S) {
      return false;
    }
    if (seenNonces.has(nonce)) return false;
    let sigBytes: Uint8Array;
    try {
      sigBytes = fromB64(sig);
    } catch {
      return false;
    }
    const grant = { serverId, kind, command, nonce, ts };
    const ok = execKeys.some((k) => verifyExecGrant(k, grant, sigBytes));
    if (ok) {
      seenNonces.set(nonce, now());
      const cutoff = now() - NONCE_TTL_MS;
      for (const [n, ti] of seenNonces) if (ti < cutoff) seenNonces.delete(n);
    }
    return ok;
  };

  return {
    setKeys: (keysB64: string[]) => {
      execKeys = keysB64.map(fromB64);
    },
    verify,
  };
};
