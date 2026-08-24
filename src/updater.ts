import { createHash, createPublicKey, verify } from 'node:crypto';
import { chmodSync, renameSync, writeFileSync } from 'node:fs';
import type { AgentConfig } from './config';
import { UPDATE_PUBKEY } from './pubkey';

/**
 * Identify which of the published builds fits this machine, e.g. `linux-x64`.
 *
 * @param platform - Defaults to the running platform; a parameter only so the
 * mapping can be exercised for hosts this process is not running on.
 * @param arch - Defaults to the running architecture.
 *
 * @remarks
 * Anything that is not Windows or macOS is treated as Linux, and any
 * architecture that is not arm64 as x64. The key selects both the download and
 * the checksum it is checked against, so a wrong guess cannot install a foreign
 * binary — it fails verification and no update happens.
 */
export const platformKey = (
  platform: string = process.platform,
  arch: string = process.arch,
): string => {
  const os = platform === 'win32' ? 'windows' : platform === 'darwin' ? 'darwin' : 'linux';
  return `${os}-${arch === 'arm64' ? 'arm64' : 'x64'}`;
};

/** What the control plane advertises: a version and, per platform, its digest and signature. */
type VersionInfo = {
  version: string;
  builds?: Record<string, { sha256?: string; signature?: string }>;
};

/**
 * Download the advertised build, verify it, and swap it on disk without restarting.
 *
 * @param buildVersion - Version currently running; an identical advertised
 * version means there is nothing to do.
 * @returns `true` once a verified newer binary is in place and only a restart
 * is missing. `false` covers everything else — no new version, a failed
 * download, and every verification failure. There is no third outcome where an
 * unverified binary is installed and a warning printed.
 *
 * @remarks
 * Self-update is the most dangerous thing this program does: it replaces the
 * code that runs on the host, often as root. So the binary has to clear two
 * independent bars, and neither is optional.
 *
 * **Integrity.** The SHA-256 of the downloaded bytes must equal the digest the
 * manifest advertises for this platform. No advertised digest means the server
 * has no verified build to offer, and the update is abandoned rather than
 * treated as a bare download.
 *
 * **Authenticity.** That digest must carry an Ed25519 signature from the key
 * embedded in this binary at build time. The checksum alone settles nothing
 * about origin: it travels from the same host as the binary, so anyone able to
 * serve a modified binary can serve a matching checksum with it. Only a
 * signature made with a key that never sits on that host distinguishes a build
 * the maintainers produced from one the API — or whoever took it over — is
 * merely hosting.
 *
 * With no embedded public key the agent refuses to update at all. Warning and
 * installing anyway would leave a build with no verifiable origin running on
 * every machine in the fleet; staying on a known older version is the safer of
 * the two failures, and it is loud enough in the logs to be noticed.
 *
 * Swapping the file while running is safe: the live process keeps its code in
 * memory, so the new binary only takes effect at the next start. The restart is
 * left to the caller, which waits for the agent to be idle — see index.ts.
 */
export const stageUpdate = async (cfg: AgentConfig, buildVersion: string): Promise<boolean> => {
  try {
    const res = await fetch(`${cfg.apiUrl}/agent/version`);
    if (!res.ok) return false;
    const info = (await res.json()) as VersionInfo;
    if (!info.version || info.version === buildVersion) return false;

    const plat = platformKey();
    const dl = await fetch(`${cfg.apiUrl}/agent/bin/${plat}`);
    if (!dl.ok) return false;
    const buf = Buffer.from(await dl.arrayBuffer());
    const got = createHash('sha256').update(buf).digest('hex');

    // 1) Integrity — mandatory, no digest means no verified build to install.
    const expected = info.builds?.[plat]?.sha256;
    if (!expected) {
      console.error('update aborted: no verified build for platform');
      return false;
    }
    if (got !== expected) {
      console.error('update aborted: checksum mismatch');
      return false;
    }

    // 2) Authenticity — ed25519 over the digest, verified against the key
    // compiled into this binary, not one fetched alongside the download.
    if (UPDATE_PUBKEY) {
      const sig = info.builds?.[plat]?.signature;
      if (!sig) {
        console.error('update aborted: missing signature');
        return false;
      }
      try {
        const pub = createPublicKey({
          key: Buffer.from(UPDATE_PUBKEY, 'base64'),
          format: 'der',
          type: 'spki',
        });
        if (!verify(null, Buffer.from(got, 'hex'), pub, Buffer.from(sig, 'base64'))) {
          console.error('update aborted: signature verification failed');
          return false;
        }
      } catch (e) {
        console.error('update aborted: signature error', (e as Error).message);
        return false;
      }
    } else {
      // No key was compiled in, so authenticity cannot be established at all:
      // refuse rather than fall back to the checksum, which proves only that
      // the download matches what the same host advertised.
      console.error(
        'update aborted: no embedded public key, signature cannot be verified. ' +
          'Build the agent with UPDATE_PUBKEY set (see scripts/gen-update-key.ts).',
      );
      return false;
    }

    // Write beside the target and rename over it: a crash mid-write leaves the
    // old working binary in place, never a truncated one.
    const target = process.execPath;
    const tmp = `${target}.new`;
    writeFileSync(tmp, buf);
    if (process.platform !== 'win32') chmodSync(tmp, 0o755);
    renameSync(tmp, target);
    console.log(`update ${buildVersion} → ${info.version} staged (will apply when idle)`);
    return true;
  } catch (e) {
    console.error('update check failed', (e as Error).message);
    return false;
  }
};
