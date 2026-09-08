import { afterEach, beforeEach, describe, expect, test } from 'bun:test';
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import { formatVersion, highestTag } from './bump-version';

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

// Module scope, not inside one describe: every block below writes to the same
// scratch version file, and a suite that only set it up for the first one would
// leave the others reading whatever the previous test left behind.
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

describe('bump-version', () => {
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

// The failure this whole `--base` argument exists for. A routine fix commit
// hand-edited version.ts to 1.2.2 while the tags had already reached 1.2.3. CI
// recomputed 1.2.3, committed the bump, and died on `git tag` — every run after
// it did the same, so agent releases stayed blocked.
describe('bumping from the last released tag', () => {
  const bumpWithBase = async (kind: string, base: string) => {
    const proc = Bun.spawn(['bun', 'run', script, kind, '--base', base], {
      env: { ...process.env, SERVOR_VERSION_FILE: versionFile, GITHUB_OUTPUT: githubOutput },
      stdout: 'pipe',
      stderr: 'pipe',
    });
    const [stdout, stderr] = await Promise.all([
      new Response(proc.stdout).text(),
      new Response(proc.stderr).text(),
    ]);
    return { code: await proc.exited, stdout, stderr };
  };

  test('a tag ahead of the file wins, so the new version cannot collide', async () => {
    writeFileSync(versionFile, SOURCE('1.2.2'));
    const { code } = await bumpWithBase('patch', '1.2.3');
    expect(code).toBe(0);
    expect(versionOnDisk()).toBe('1.2.4');
  });

  test('a file ahead of the tags is honoured', async () => {
    writeFileSync(versionFile, SOURCE('1.3.0'));
    await bumpWithBase('patch', '1.2.3');
    expect(versionOnDisk()).toBe('1.3.1');
  });

  test('the two agreeing behaves exactly as before', async () => {
    writeFileSync(versionFile, SOURCE('1.2.3'));
    await bumpWithBase('patch', '1.2.3');
    expect(versionOnDisk()).toBe('1.2.4');
  });

  test('the tag may carry its agent-v prefix', async () => {
    writeFileSync(versionFile, SOURCE('1.2.2'));
    await bumpWithBase('patch', 'agent-v1.2.3');
    expect(versionOnDisk()).toBe('1.2.4');
  });

  test('the reported jump names both sources when they disagreed', async () => {
    writeFileSync(versionFile, SOURCE('1.2.2'));
    const { stdout } = await bumpWithBase('patch', '1.2.3');
    expect(stdout).toContain('source said 1.2.2');
  });

  // A repository with no agent tag yet: the workflow passes an empty string.
  test('an empty base falls back to the file', async () => {
    writeFileSync(versionFile, SOURCE('1.2.2'));
    const { code } = await bumpWithBase('patch', '');
    expect(code).toBe(0);
    expect(versionOnDisk()).toBe('1.2.3');
  });

  test('an unparseable base is reported but does not stop the release', async () => {
    writeFileSync(versionFile, SOURCE('1.2.2'));
    const { code, stderr } = await bumpWithBase('patch', 'not-a-version');
    expect(code).toBe(0);
    expect(stderr).toContain('unparseable --base');
    expect(versionOnDisk()).toBe('1.2.3');
  });

  test('a major tag ahead of the file is still respected', async () => {
    writeFileSync(versionFile, SOURCE('1.9.9'));
    await bumpWithBase('patch', '2.0.0');
    expect(versionOnDisk()).toBe('2.0.1');
  });
});

describe('picking the highest tag', () => {
  test('tags sort numerically, not as text', () => {
    // The bug a plain `sort` would bring back: "1.2.9" > "1.2.10" as strings.
    expect(formatVersion(highestTag(['agent-v1.2.9', 'agent-v1.2.10'])!)).toBe('1.2.10');
  });

  test('a double-digit minor outranks a single-digit one', () => {
    expect(formatVersion(highestTag(['agent-v1.9.0', 'agent-v1.10.0'])!)).toBe('1.10.0');
  });

  test('unparseable entries are ignored rather than crashing the release', () => {
    expect(formatVersion(highestTag(['agent-v1.2.3', 'agent-vnightly', ''])!)).toBe('1.2.3');
  });

  test('no tags at all yields nothing to compare against', () => {
    expect(highestTag([])).toBeNull();
    expect(highestTag(['not-an-agent-tag'])).toBeNull();
  });
});
