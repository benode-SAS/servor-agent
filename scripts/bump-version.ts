/**
 * Bump `BUILD_VERSION` in src/version.ts. Run by CI on any change under apps/agent.
 *
 * ```sh
 * bun run scripts/bump-version.ts [patch|minor|major] [--base <version>]
 * ```
 *
 * @remarks
 * The version lives in source because the compiled binary has to carry it —
 * there is no package.json inside an executable. Rewriting the file is the
 * whole job; write-manifest.ts is what later tells the API this version exists,
 * and only after the binaries have actually been built.
 *
 * `--base` is the last version the pipeline actually **released**, read from the
 * `agent-v*` tags. The next version is computed from whichever of the two is
 * higher, the file or that tag — see `higherVersion` for why the file alone is
 * not trustworthy.
 *
 * Exits non-zero on an unknown bump kind or if the constant cannot be found, so
 * a broken release pipeline stops here rather than shipping an unchanged
 * version under a new tag.
 *
 * @module
 */
import { readFileSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';

export type Semver = [number, number, number];
export type BumpKind = 'patch' | 'minor' | 'major';

export const parseVersion = (value: string | undefined | null): Semver | null => {
  const m = value
    ?.trim()
    .replace(/^agent-v/, '')
    .match(/^(\d+)\.(\d+)\.(\d+)$/);
  return m ? [Number(m[1]), Number(m[2]), Number(m[3])] : null;
};

export const formatVersion = ([major, minor, patch]: Semver): string =>
  `${major}.${minor}.${patch}`;

export const compareVersions = (a: Semver, b: Semver): number =>
  a[0] - b[0] || a[1] - b[1] || a[2] - b[2];

/**
 * The higher of the version in source and the last released tag.
 *
 * @remarks
 * These two are supposed to agree and repeatedly have not. The file is ordinary
 * source: a hand edit, a merge or a rebase can move it, and one did — a routine
 * fix commit set it to 1.2.2 while the tags had already reached 1.2.3. The next
 * run then recomputed 1.2.3, committed the bump, and died on `git tag` because
 * that tag existed. Every run after it did the same, so agent releases stayed
 * blocked until someone edited the file by hand.
 *
 * Taking the maximum makes the drift self-correcting in both directions: a file
 * pushed ahead of the tags is honoured, and a file that fell behind them is
 * ignored. The tag is what says a version was truly published, so it is the one
 * a new version must never collide with.
 */
export const higherVersion = (fileVersion: Semver, base: Semver | null): Semver =>
  base && compareVersions(base, fileVersion) > 0 ? base : fileVersion;

export const bumpVersion = ([major, minor, patch]: Semver, kind: BumpKind): Semver =>
  kind === 'major'
    ? [major + 1, 0, 0]
    : kind === 'minor'
      ? [major, minor + 1, 0]
      : [major, minor, patch + 1];

/** Highest `agent-v*` tag in a `git tag -l` listing, or null if there is none. */
export const highestTag = (tags: readonly string[]): Semver | null =>
  tags
    .map(parseVersion)
    .filter((v): v is Semver => v !== null)
    .sort(compareVersions)
    .at(-1) ?? null;

if (import.meta.main) {
  const args = process.argv.slice(2);
  const baseIndex = args.indexOf('--base');
  const baseArg = baseIndex === -1 ? undefined : args[baseIndex + 1];
  const kind = (args.find((a) => !a.startsWith('--') && a !== baseArg) ?? 'patch') as BumpKind;

  if (!['patch', 'minor', 'major'].includes(kind)) {
    console.error(`unknown bump '${kind}' — expected patch, minor or major`);
    process.exit(1);
  }

  // An unparseable `--base` is not fatal: an empty string is exactly what the
  // workflow passes for a repository with no agent tag yet.
  const base = parseVersion(baseArg);
  if (baseArg?.trim() && !base) {
    console.error(`ignoring unparseable --base '${baseArg}'`);
  }

  // SERVOR_VERSION_FILE retargets the rewrite; nothing sets it in the pipeline.
  const file = process.env.SERVOR_VERSION_FILE ?? join(import.meta.dir, '..', 'src', 'version.ts');
  const source = readFileSync(file, 'utf-8');

  const match = source.match(/export const BUILD_VERSION = '(\d+)\.(\d+)\.(\d+)';/);
  const fileVersion = match ? parseVersion(`${match[1]}.${match[2]}.${match[3]}`) : null;
  if (!match || !fileVersion) {
    console.error('could not find BUILD_VERSION in src/version.ts');
    process.exit(1);
  }

  const from = higherVersion(fileVersion, base);
  const next = bumpVersion(from, kind);
  const nextText = formatVersion(next);

  writeFileSync(file, source.replace(match[0], `export const BUILD_VERSION = '${nextText}';`));

  // Consumed by the release workflow to name the tag and the release.
  const out = process.env.GITHUB_OUTPUT;
  if (out) writeFileSync(out, `version=${nextText}\n`, { flag: 'a' });

  const fileText = formatVersion(fileVersion);
  const note =
    compareVersions(from, fileVersion) > 0
      ? ` (source said ${fileText}, tags said ${formatVersion(from)})`
      : '';
  console.log(`${formatVersion(from)} -> ${nextText}${note}`);
}
