// Generate the ed25519 keypair for agent auto-update signing.
//   bun run apps/agent/scripts/gen-update-key.ts
// → put UPDATE_PUBKEY in apps/agent/src/pubkey.ts (commit it),
//   and AGENT_UPDATE_PRIVATE_KEY in the API env (keep it secret).
import { generateKeyPairSync } from 'node:crypto';

const { publicKey, privateKey } = generateKeyPairSync('ed25519');
const pub = publicKey.export({ format: 'der', type: 'spki' }).toString('base64');
const priv = privateKey.export({ format: 'der', type: 'pkcs8' }).toString('base64');

process.stdout.write('\n— apps/agent/src/pubkey.ts —\n');
process.stdout.write(`export const UPDATE_PUBKEY = '${pub}';\n`);
process.stdout.write('\n— API .env —\n');
process.stdout.write(`AGENT_UPDATE_PRIVATE_KEY=${priv}\n\n`);
