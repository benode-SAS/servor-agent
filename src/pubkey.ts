// ed25519 public key (base64 SPKI/DER) verifying auto-update binaries.
// Generate the keypair with: bun run scripts/gen-update-key.ts
//   → put the public key here, the private key in the API env AGENT_UPDATE_PRIVATE_KEY.
// Empty string = signature verification disabled (dev only — DO NOT ship empty).
export const UPDATE_PUBKEY = '';
