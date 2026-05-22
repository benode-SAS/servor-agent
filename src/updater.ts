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

export const checkUpdate = async (cfg: AgentConfig, buildVersion: string) => {
  try {
    const res = await fetch(`${cfg.apiUrl}/agent/version`);
    if (!res.ok) return;
    const info = (await res.json()) as VersionInfo;
    if (!info.version || info.version === buildVersion) return;

    const plat = platformKey();
    const dl = await fetch(`${cfg.apiUrl}/agent/bin/${plat}`);
    if (!dl.ok) return;
    const buf = Buffer.from(await dl.arrayBuffer());
    const got = createHash('sha256').update(buf).digest('hex');

    // 1) Integrity: checksum.
    const expected = info.builds?.[plat]?.sha256;
    if (expected && got !== expected) {
      console.error('update aborted: checksum mismatch');
      return;
    }

    // 2) Authenticity: ed25519 signature over the sha256 (defends against a
    // compromised control plane / CDN). Mandatory when a public key is embedded.
    if (UPDATE_PUBKEY) {
      const sig = info.builds?.[plat]?.signature;
      if (!sig) {
        console.error('update aborted: missing signature');
        return;
      }
      try {
        const pub = createPublicKey({
          key: Buffer.from(UPDATE_PUBKEY, 'base64'),
          format: 'der',
          type: 'spki',
        });
        if (!verify(null, Buffer.from(got, 'hex'), pub, Buffer.from(sig, 'base64'))) {
          console.error('update aborted: signature verification failed');
          return;
        }
      } catch (e) {
        console.error('update aborted: signature error', (e as Error).message);
        return;
      }
    } else {
      console.warn('update: no embedded public key — signature NOT verified (dev only)');
    }

    const target = process.execPath;
    const tmp = `${target}.new`;
    writeFileSync(tmp, buf);
    if (process.platform !== 'win32') chmodSync(tmp, 0o755);
    renameSync(tmp, target);
    console.log(`updated ${buildVersion} → ${info.version}, restarting`);
    process.exit(0); // service manager (systemd/launchd/scheduled task) relaunches
  } catch (e) {
    console.error('update check failed', (e as Error).message);
  }
};
