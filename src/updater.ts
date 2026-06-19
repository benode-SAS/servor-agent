import { createHash, createPublicKey, verify } from 'node:crypto';
import { chmodSync, renameSync, writeFileSync } from 'node:fs';
import type { AgentConfig } from './config';
import { UPDATE_PUBKEY } from './pubkey';

export const platformKey = (): string => {
  const os =
    process.platform === 'win32' ? 'windows' : process.platform === 'darwin' ? 'darwin' : 'linux';
  const arch = process.arch === 'arm64' ? 'arm64' : 'x64';
  return `${os}-${arch}`;
};

type VersionInfo = {
  version: string;
  builds?: Record<string, { sha256?: string; signature?: string }>;
};

// Download + verify the new binary and swap it on disk, WITHOUT restarting.
// Returns true once a verified newer build is staged. The caller restarts only
// when the agent is idle (graceful drain) — see index.ts. Swapping the file is
// safe while running: the live process keeps the old code in memory until exit.
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

    // 1) Integrity: checksum is MANDATORY. No advertised checksum for this
    // platform → the server has no verified build, so never swap.
    const expected = info.builds?.[plat]?.sha256;
    if (!expected) {
      console.error('update aborted: no verified build for platform');
      return false;
    }
    if (got !== expected) {
      console.error('update aborted: checksum mismatch');
      return false;
    }

    // 2) Authenticity: ed25519 signature over the sha256 (defends against a
    // compromised control plane / CDN). Mandatory when a public key is embedded.
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
      console.warn('update: no embedded public key — signature NOT verified (dev only)');
    }

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
