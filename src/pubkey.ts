// ed25519 public key (base64 SPKI/DER) verifying auto-update binaries.
// Generate the keypair with: bun run scripts/gen-update-key.ts
//   → put the public key here, the private key in the API env AGENT_UPDATE_PRIVATE_KEY.
// Empty string = the agent REFUSES to self-update (fail closed). A release
// build must set this, or auto-update is inert.
export const UPDATE_PUBKEY = 'MCowBQYDK2VwAyEAMk9aHGN/6q08ivnExsZSRGWOJ2ZRTbePkRGqwka9mFw=';
