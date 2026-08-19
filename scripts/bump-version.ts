// Bump the agent's build version. Called by CI on any change under apps/agent.
//
//   bun run scripts/bump-version.ts [patch|minor|major]
//
// The version lives in src/version.ts because the compiled binary has to carry
// it — there is no package.json inside the executable. write-manifest.ts copies
// it into dist/manifest.json after the binaries exist, so the API can never
// advertise a version nobody built.
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

// Consumed by the workflow to name the tag and the release.
const out = process.env.GITHUB_OUTPUT;
if (out) writeFileSync(out, `version=${next}\n`, { flag: 'a' });

console.log(`${match[1]}.${match[2]}.${match[3]} -> ${next}`);
