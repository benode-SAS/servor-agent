// Vendored from packages/shared/src/crypto/wipe.ts — do not edit here.
//
// The agent ships as an independent, auditable artefact: a reader must be
// able to see every line that decides whether a command runs, without
// resolving a private Servor package. `bun run protocol:check` fails if this
// copy drifts from the original, because a guard that disagrees with the one
// on the control plane is worse than no guard.

export const wipe = (...buffers: (Uint8Array | undefined | null)[]): void => {
  for (const b of buffers) {
    if (b && b.length > 0) b.fill(0);
  }
};

export const concat = (...arrays: Uint8Array[]): Uint8Array => {
  let total = 0;
  for (const a of arrays) total += a.length;
  const out = new Uint8Array(total);
  let off = 0;
  for (const a of arrays) {
    out.set(a, off);
    off += a.length;
  }
  return out;
};

export const randomBytes = (length: number): Uint8Array => {
  const b = new Uint8Array(length);
  crypto.getRandomValues(b);
  return b;
};
