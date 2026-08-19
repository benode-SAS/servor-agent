/**
 * Generate the Ed25519 keypair that signs agent auto-update binaries.
 *
 * ```sh
 * bun run apps/agent/scripts/gen-update-key.ts
 * ```
 *
 * The public half goes in apps/agent/src/pubkey.ts and is committed; the
 * private half goes in the API environment as AGENT_UPDATE_PRIVATE_KEY.
 *
 * @remarks
 * The split is the entire point of the scheme. The public key is compiled into
 * every agent, so each machine can check for itself who produced the binary it
 * is about to run. The private key must live somewhere an attacker who takes
 * over the API host still cannot reach — put it there and a compromised control
 * plane can serve a modified binary, but cannot make one the fleet accepts.
 *
 * Both keys are printed to stdout, which means this belongs on a trusted
 * machine and not in CI logs. Rotating the pair requires shipping a new agent
 * build: agents already deployed only trust the key they were compiled with.
 *
 * @module
 */
import { generateKeyPairSync } from 'node:crypto';

const { publicKey, privateKey } = generateKeyPairSync('ed25519');
const pub = publicKey.export({ format: 'der', type: 'spki' }).toString('base64');
const priv = privateKey.export({ format: 'der', type: 'pkcs8' }).toString('base64');

process.stdout.write('\n— apps/agent/src/pubkey.ts —\n');
process.stdout.write(`export const UPDATE_PUBKEY = '${pub}';\n`);
process.stdout.write('\n— API .env —\n');
process.stdout.write(`AGENT_UPDATE_PRIVATE_KEY=${priv}\n\n`);
