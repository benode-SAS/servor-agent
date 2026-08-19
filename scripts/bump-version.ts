/**
 * Bump `BUILD_VERSION` in src/version.ts. Run by CI on any change under apps/agent.
 *
 * ```sh
 * bun run scripts/bump-version.ts [patch|minor|major]
 * ```
 *
 * @remarks
 * The version lives in source because the compiled binary has to carry it —
 * there is no package.json inside an executable. Rewriting the file is the
 * whole job; write-manifest.ts is what later tells the API this version exists,
 * and only after the binaries have actually been built.
 *
 * Exits non-zero on an unknown bump kind or if the constant cannot be found, so
 * a broken release pipeline stops here rather than shipping an unchanged
 * version under a new tag.
 *
 * @module
 */
import { readFileSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';

const kind = (process.argv[2] ?? 'patch') as 'patch' | 'minor' | 'major';
if (!['patch', 'minor', 'major'].includes(kind)) {
  console.error(`unknown bump '${kind}' — expected patch, minor or major`);
  process.exit(1);
}

const file = join(import.meta.dir, '..', 'src', 'version.ts');
const source = readFileSync(file, 'utf-8');

const match = source.match(/export const BUILD_VERSION = '(\d+)\.(\d+)\.(\d+)';/);
if (!match) {
  console.error('could not find BUILD_VERSION in src/version.ts');
  process.exit(1);
}

const [major, minor, patch] = [Number(match[1]), Number(match[2]), Number(match[3])];
const next =
  kind === 'major'
    ? `${major + 1}.0.0`
    : kind === 'minor'
      ? `${major}.${minor + 1}.0`
      : `${major}.${minor}.${patch + 1}`;

writeFileSync(file, source.replace(match[0], `export const BUILD_VERSION = '${next}';`));

// Consumed by the release workflow to name the tag and the release.
const out = process.env.GITHUB_OUTPUT;
if (out) writeFileSync(out, `version=${next}\n`, { flag: 'a' });

console.log(`${match[1]}.${match[2]}.${match[3]} -> ${next}`);
