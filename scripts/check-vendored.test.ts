import { afterEach, beforeEach, describe, expect, test } from 'bun:test';
import { createHash } from 'node:crypto';
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';

const script = join(import.meta.dir, 'check-vendored.ts');

const SHARED_SOURCE = 'export const validateCommand = () => ({ ok: true });\n';
const sha256 = (text: string) => createHash('sha256').update(text).digest('hex');

let root: string;
let agentDir: string;

/** Lay down a fake monorepo: an agent workspace plus the shared package it copies from. */
const fixture = (manifest: Record<string, { source: string; sha256: string }>) => {
  const protocolDir = join(agentDir, 'src', 'protocol');
  mkdirSync(protocolDir, { recursive: true });
  writeFileSync(join(protocolDir, 'VENDORED.json'), JSON.stringify(manifest, null, 2));
};

const writeSource = (relative: string, contents: string) => {
  const path = join(root, relative);
  mkdirSync(dirname(path), { recursive: true });
  writeFileSync(path, contents);
};

const check = async () => {
  const proc = Bun.spawn(['bun', 'run', script], {
    env: { ...process.env, SERVOR_AGENT_DIR: agentDir },
    stdout: 'pipe',
    stderr: 'pipe',
  });
  const [stdout, stderr] = await Promise.all([
    new Response(proc.stdout).text(),
    new Response(proc.stderr).text(),
  ]);
  return { code: await proc.exited, stdout, stderr };
};

describe('check-vendored', () => {
  beforeEach(() => {
    root = mkdtempSync(join(tmpdir(), 'servor-agent-vendor-'));
    agentDir = join(root, 'apps', 'agent');
  });

  afterEach(() => {
    rmSync(root, { recursive: true, force: true });
  });

  test('a copy whose source still hashes the same passes', async () => {
    writeSource('packages/shared/src/utils/command-guards.ts', SHARED_SOURCE);
    fixture({
      'command-guards.ts': {
        source: 'packages/shared/src/utils/command-guards.ts',
        sha256: sha256(SHARED_SOURCE),
      },
    });
    const { code, stdout } = await check();
    expect(code).toBe(0);
    expect(stdout).toContain('ok    command-guards.ts');
    expect(stdout).toContain('1 file(s) in sync');
  });

  test('a source that has changed since it was copied fails', async () => {
    writeSource(
      'packages/shared/src/utils/command-guards.ts',
      `${SHARED_SOURCE}// one more rule\n`,
    );
    fixture({
      'command-guards.ts': {
        source: 'packages/shared/src/utils/command-guards.ts',
        sha256: sha256(SHARED_SOURCE),
      },
    });
    const { code, stderr } = await check();
    expect(code).toBe(1);
    expect(stderr).toContain('DRIFT command-guards.ts');
    expect(stderr).toContain('1 vendored file(s) out of date');
  });

  test('even a changed comment counts as drift', async () => {
    writeSource(
      'packages/shared/src/utils/command-guards.ts',
      SHARED_SOURCE.replace('export', '// note\nexport'),
    );
    fixture({
      'command-guards.ts': {
        source: 'packages/shared/src/utils/command-guards.ts',
        sha256: sha256(SHARED_SOURCE),
      },
    });
    expect((await check()).code).toBe(1);
  });

  test('an absent source is skipped, because that is not a mismatch', async () => {
    fixture({
      'command-guards.ts': {
        source: 'packages/shared/src/utils/command-guards.ts',
        sha256: sha256(SHARED_SOURCE),
      },
    });
    const { code, stdout } = await check();
    expect(code).toBe(0);
    expect(stdout).toContain('skip  command-guards.ts');
    expect(stdout).toContain('nothing to check');
  });

  test('present sources are still checked when others are absent', async () => {
    writeSource('packages/shared/src/utils/command-guards.ts', SHARED_SOURCE);
    fixture({
      'command-guards.ts': {
        source: 'packages/shared/src/utils/command-guards.ts',
        sha256: sha256(SHARED_SOURCE),
      },
      'exec-sign.ts': {
        source: 'packages/shared/src/crypto/exec-sign.ts',
        sha256: sha256('anything'),
      },
    });
    const { code, stdout } = await check();
    expect(code).toBe(0);
    expect(stdout).toContain('skip  exec-sign.ts');
    expect(stdout).toContain('1 file(s) in sync');
  });

  test('one drift among several files still fails the whole check', async () => {
    writeSource('packages/shared/src/utils/command-guards.ts', SHARED_SOURCE);
    writeSource('packages/shared/src/crypto/exec-sign.ts', 'export const signed = true;\n');
    fixture({
      'command-guards.ts': {
        source: 'packages/shared/src/utils/command-guards.ts',
        sha256: sha256(SHARED_SOURCE),
      },
      'exec-sign.ts': {
        source: 'packages/shared/src/crypto/exec-sign.ts',
        sha256: sha256('something else entirely'),
      },
    });
    const { code, stderr } = await check();
    expect(code).toBe(1);
    expect(stderr).toContain('DRIFT exec-sign.ts');
  });
});

describe('the real vendored copies', () => {
  test('src/protocol/ is in sync with packages/shared', async () => {
    const proc = Bun.spawn(['bun', 'run', script], { stdout: 'pipe', stderr: 'pipe' });
    const stderr = await new Response(proc.stderr).text();
    expect(stderr).not.toContain('DRIFT');
    expect(await proc.exited).toBe(0);
  });
});
