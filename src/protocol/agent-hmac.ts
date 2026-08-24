// Vendored from packages/shared/src/crypto/agent-hmac.ts — do not edit here.
//
// The agent ships as an independent, auditable artefact: a reader must be
// able to see every line that decides whether a command runs, without
// resolving a private Servor package. `bun run protocol:check` fails if this
// copy drifts from the original, because a guard that disagrees with the one
// on the control plane is worse than no guard.

// ── Agent request authentication ────────────────────────────────────────────
// Every outbound agent request carries an HMAC over the per-server secret. This
// module owns the *message* that gets signed; each side applies HMAC-SHA256 to
// it with its own primitive, so the bytes are guaranteed identical while the
// package stays free of `node:crypto` and portable to the browser.

const enc = new TextEncoder();

const AGENT_HMAC_DOMAIN = 'servor/agent-hmac/v1';

/**
 * What a signature is allowed to authenticate.
 *
 * @remarks
 * One secret signs several kinds of request, so the kind is inside the signed
 * bytes. Without it a signature captured from one exchange is a valid signature
 * for another whose body happens to match — a config fetch replayed as a tunnel
 * handshake, for instance.
 */
export type AgentMessageKind = 'ingest' | 'tunnel' | 'config' | 'result';

const u32 = (n: number): Uint8Array => {
  const b = new Uint8Array(4);
  new DataView(b.buffer).setUint32(0, n, false);
  return b;
};

export type AgentMessage = {
  kind: AgentMessageKind;
  serverId: string;
  /** Unix seconds, as a decimal string. */
  timestamp: string;
  /** The exact bytes being authenticated: a JSON body, or a short descriptor. */
  body: string;
};

/**
 * Length-prefixed framing, so no field boundary can be moved by its content.
 *
 * @remarks
 * The previous framing was `${timestamp}.${body}`, which had two problems. The
 * separator also occurs inside a timestamp that `Number.parseInt` happily
 * accepts — `"170.5"` parses to 170 and passes the skew check — so the boundary
 * between the two fields could be shifted. And nothing named the kind of
 * request, so the same signature authenticated any exchange with a matching
 * body.
 *
 * Mirrors `exec-sign.ts`, which frames operator grants the same way and for the
 * same reason.
 */
export const canonicalAgentMessage = (message: AgentMessage): Uint8Array => {
  const parts: Uint8Array[] = [enc.encode(AGENT_HMAC_DOMAIN)];
  for (const field of [message.kind, message.serverId, message.timestamp, message.body]) {
    const bytes = enc.encode(field);
    parts.push(u32(bytes.length), bytes);
  }
  let total = 0;
  for (const p of parts) total += p.length;
  const out = new Uint8Array(total);
  let offset = 0;
  for (const p of parts) {
    out.set(p, offset);
    offset += p.length;
  }
  return out;
};

/**
 * The pre-v1 message, kept only so a control plane can still verify agents that
 * have not picked up their update yet.
 *
 * @remarks
 * Never produce this. It exists to be accepted, loudly, for one release.
 */
export const legacyAgentMessage = (timestamp: string, body: string): Uint8Array =>
  enc.encode(`${timestamp}.${body}`);

/**
 * A timestamp this codebase is willing to treat as one.
 *
 * @remarks
 * `Number.parseInt` stops at the first non-digit, so it accepts `"170.5"`,
 * `"170abc"` and `" 170"` alike — which is what let the old framing be
 * ambiguous in the first place. Digits only, and short enough that no caller
 * can smuggle a payload through the field.
 */
export const isCanonicalTimestamp = (value: string): boolean => /^\d{1,15}$/.test(value);
