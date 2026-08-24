import { afterEach, beforeEach, describe, expect, test } from 'bun:test';
import { createHash } from 'node:crypto';
import { mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';

const script = join(import.meta.dir, 'vendor-sync.ts');
const sha256 = (text: string) => createHash('sha256').update(text).digest('hex');

let root: string;
let agentDir: string;
let protocolDir: string;

const writeManifest = (manifest: Record<string, { source: string; sha256: string }>) => {
  mkdirSync(protocolDir, { recursive: true });
  writeFileSync(join(protocolDir, 'VENDORED.json'), JSON.stringify(manifest, null, 2));
};

const writeSource = (relative: string, contents: string) => {
  const path = join(root, relative);
  mkdirSync(dirname(path), { recursive: true });
  writeFileSync(path, contents);
};

const sync = async () => {
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

const copy = (name: string) => readFileSync(join(protocolDir, name), 'utf-8');
const manifest = () =>
  JSON.parse(readFileSync(join(protocolDir, 'VENDORED.json'), 'utf-8')) as Record<
    string,
    { source: string; sha256: string }
  >;

describe('vendor-sync', () => {
  beforeEach(() => {
    root = mkdtempSync(join(tmpdir(), 'servor-agent-sync-'));
    agentDir = join(root, 'apps', 'agent');
    protocolDir = join(agentDir, 'src', 'protocol');
  });

  afterEach(() => {
    rmSync(root, { recursive: true, force: true });
  });

  test('copies the source and records its hash', async () => {
    const source = 'export const guard = true;\n';
    writeSource('packages/shared/src/utils/command-guards.ts', source);
    writeManifest({
      'command-guards.ts': {
        source: 'packages/shared/src/utils/command-guards.ts',
        sha256: 'stale',
      },
    });

    const { code, stdout } = await sync();
    expect(code).toBe(0);
    expect(stdout).toContain('update command-guards.ts');
    expect(copy('command-guards.ts')).toContain(source);
    expect(manifest()['command-guards.ts']?.sha256).toBe(sha256(source));
  });

  test('the hash recorded is the source, not the copy — that is what check-vendored compares', async () => {
    const source = 'export const guard = true;\n';
    writeSource('packages/shared/src/utils/command-guards.ts', source);
    writeManifest({
      'command-guards.ts': { source: 'packages/shared/src/utils/command-guards.ts', sha256: '' },
    });

    await sync();
    expect(manifest()['command-guards.ts']?.sha256).toBe(sha256(source));
    expect(manifest()['command-guards.ts']?.sha256).not.toBe(sha256(copy('command-guards.ts')));
  });

  test('prepends a header naming where the file came from', async () => {
    writeSource('packages/shared/src/crypto/wipe.ts', 'export const wipe = () => {};\n');
    writeManifest({
      'wipe.ts': { source: 'packages/shared/src/crypto/wipe.ts', sha256: '' },
    });

    await sync();
    const written = copy('wipe.ts');
    expect(written.startsWith('// Vendored from packages/shared/src/crypto/wipe.ts')).toBe(true);
    expect(written).toContain('do not edit here');
  });

  test('rewrites an import of another vendored file to sit beside it', async () => {
    // The copies have to resolve against each other: a standalone checkout of
    // the agent has no packages/shared to reach back into.
    writeSource(
      'packages/shared/src/utils/command-guards.ts',
      "import { PATTERNS } from '../constants/command-blacklist';\nexport const guard = PATTERNS;\n",
    );
    writeSource(
      'packages/shared/src/constants/command-blacklist.ts',
      'export const PATTERNS = [];\n',
    );
    writeManifest({
      'command-guards.ts': { source: 'packages/shared/src/utils/command-guards.ts', sha256: '' },
      'command-blacklist.ts': {
        source: 'packages/shared/src/constants/command-blacklist.ts',
        sha256: '',
      },
    });

    await sync();
    expect(copy('command-guards.ts')).toContain("from './command-blacklist'");
    expect(copy('command-guards.ts')).not.toContain('../constants/');
  });

  test('leaves a package import alone', async () => {
    writeSource(
      'packages/shared/src/crypto/exec-sign.ts',
      "import { ed25519 } from '@noble/curves/ed25519';\nexport const sign = ed25519;\n",
    );
    writeManifest({
      'exec-sign.ts': { source: 'packages/shared/src/crypto/exec-sign.ts', sha256: '' },
    });

    await sync();
    expect(copy('exec-sign.ts')).toContain("from '@noble/curves/ed25519'");
  });

  test('leaves a relative import of a file that is not vendored alone', async () => {
    writeSource(
      'packages/shared/src/crypto/exec-sign.ts',
      "import { helper } from './not-vendored';\nexport const sign = helper;\n",
    );
    writeManifest({
      'exec-sign.ts': { source: 'packages/shared/src/crypto/exec-sign.ts', sha256: '' },
    });

    await sync();
    expect(copy('exec-sign.ts')).toContain("from './not-vendored'");
  });

  test('running it twice changes nothing the second time', async () => {
    writeSource('packages/shared/src/crypto/wipe.ts', 'export const wipe = () => {};\n');
    writeManifest({ 'wipe.ts': { source: 'packages/shared/src/crypto/wipe.ts', sha256: '' } });

    await sync();
    const first = copy('wipe.ts');
    const firstManifest = manifest();

    const { stdout } = await sync();
    expect(copy('wipe.ts')).toBe(first);
    expect(manifest()).toEqual(firstManifest);
    expect(stdout).toContain('ok     wipe.ts');
  });

  test('a sync leaves check-vendored satisfied', async () => {
    // The two scripts are two halves of one contract; if they disagree, the
    // guard on the machine can drift from the control plane without anyone
    // noticing.
    const source = 'export const guard = true;\n';
    writeSource('packages/shared/src/utils/command-guards.ts', source);
    writeManifest({
      'command-guards.ts': {
        source: 'packages/shared/src/utils/command-guards.ts',
        sha256: 'stale',
      },
    });

    await sync();

    const check = Bun.spawn(['bun', 'run', join(import.meta.dir, 'check-vendored.ts')], {
      env: { ...process.env, SERVOR_AGENT_DIR: agentDir },
      stdout: 'pipe',
      stderr: 'pipe',
    });
    const stdout = await new Response(check.stdout).text();
    expect(await check.exited).toBe(0);
    expect(stdout).toContain('1 file(s) in sync');
  });

  test('fails loudly when a source has gone missing', async () => {
    writeManifest({
      'command-guards.ts': { source: 'packages/shared/src/utils/command-guards.ts', sha256: '' },
    });
    const { code, stderr } = await sync();
    expect(code).not.toBe(0);
    expect(stderr).toContain('ENOENT');
  });
});
