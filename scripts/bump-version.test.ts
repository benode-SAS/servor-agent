import { afterEach, beforeEach, describe, expect, test } from 'bun:test';
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

const script = join(import.meta.dir, 'bump-version.ts');

const SOURCE = (version: string) => `/** Doc comment that must survive the rewrite. */
export const BUILD_VERSION = '${version}';
`;

let dir: string;
let versionFile: string;
let githubOutput: string;

const bump = async (kind?: string) => {
  const proc = Bun.spawn(['bun', 'run', script, ...(kind === undefined ? [] : [kind])], {
    env: {
      ...process.env,
      SERVOR_VERSION_FILE: versionFile,
      GITHUB_OUTPUT: githubOutput,
    },
    stdout: 'pipe',
    stderr: 'pipe',
  });
  const [stdout, stderr] = await Promise.all([
    new Response(proc.stdout).text(),
    new Response(proc.stderr).text(),
  ]);
  return { code: await proc.exited, stdout, stderr };
};

const versionOnDisk = () =>
  readFileSync(versionFile, 'utf-8').match(/BUILD_VERSION = '([^']+)'/)?.[1];

describe('bump-version', () => {
  beforeEach(() => {
    dir = mkdtempSync(join(tmpdir(), 'servor-agent-bump-'));
    versionFile = join(dir, 'version.ts');
    githubOutput = join(dir, 'github-output');
    writeFileSync(versionFile, SOURCE('1.2.3'));
    writeFileSync(githubOutput, '');
  });

  afterEach(() => {
    rmSync(dir, { recursive: true, force: true });
  });

  test.each([
    ['patch', '1.2.4'],
    ['minor', '1.3.0'],
    ['major', '2.0.0'],
  ])('a %s bump of 1.2.3 gives %s', async (kind, expected) => {
    const { code, stdout } = await bump(kind);
    expect(code).toBe(0);
    expect(versionOnDisk()).toBe(expected);
    expect(stdout).toContain(`1.2.3 -> ${expected}`);
  });

  test('the bump kind defaults to patch', async () => {
    expect((await bump()).code).toBe(0);
    expect(versionOnDisk()).toBe('1.2.4');
  });

  test('a minor bump resets the patch, a major bump resets both', async () => {
    writeFileSync(versionFile, SOURCE('3.7.9'));
    await bump('minor');
    expect(versionOnDisk()).toBe('3.8.0');
    await bump('major');
    expect(versionOnDisk()).toBe('4.0.0');
  });

  test('the rest of the file is left alone', async () => {
    await bump('patch');
    expect(readFileSync(versionFile, 'utf-8')).toContain(
      '/** Doc comment that must survive the rewrite. */',
    );
  });

  test('the new version is exported for the release workflow', async () => {
    await bump('minor');
    expect(readFileSync(githubOutput, 'utf-8')).toBe('version=1.3.0\n');
  });

  test('an unknown bump kind fails without touching the file', async () => {
    const { code, stderr } = await bump('sideways');
    expect(code).toBe(1);
    expect(stderr).toContain("unknown bump 'sideways'");
    expect(versionOnDisk()).toBe('1.2.3');
  });

  test('a file without the constant fails rather than shipping an unchanged version', async () => {
    writeFileSync(versionFile, 'export const SOMETHING_ELSE = 1;\n');
    const { code, stderr } = await bump('patch');
    expect(code).toBe(1);
    expect(stderr).toContain('could not find BUILD_VERSION');
  });

  test('a non-semver version is not treated as bumpable', async () => {
    writeFileSync(versionFile, "export const BUILD_VERSION = '1.2';\n");
    const { code } = await bump('patch');
    expect(code).toBe(1);
  });
});
