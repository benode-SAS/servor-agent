// Verify the vendored protocol files still match their source in
// packages/shared. Run from the monorepo; skips cleanly in a standalone
// checkout, where there is nothing to compare against.
//
// Drift here is not cosmetic: these files decide whether a signature is
// accepted and whether a command is refused. A copy that disagrees with the
// control plane either breaks execution or, worse, quietly weakens a guard.
import { createHash } from 'node:crypto';
import { existsSync, readFileSync } from 'node:fs';
import { join } from 'node:path';

type Entry = { source: string; sha256: string };

const here = new URL('..', import.meta.url).pathname.replace(/^\/([A-Za-z]:)/, '$1');
const repoRoot = join(here, '..', '..');
const manifestPath = join(here, 'src', 'protocol', 'VENDORED.json');

const manifest: Record<string, Entry> = JSON.parse(readFileSync(manifestPath, 'utf-8'));

let checked = 0;
let drifted = 0;

for (const [name, entry] of Object.entries(manifest)) {
  const source = join(repoRoot, entry.source);
  if (!existsSync(source)) {
    console.log(`skip  ${name} — source not present (standalone checkout)`);
    continue;
  }
  const actual = createHash('sha256').update(readFileSync(source, 'utf-8')).digest('hex');
  checked += 1;
  if (actual === entry.sha256) {
    console.log(`ok    ${name}`);
  } else {
    drifted += 1;
    console.error(`DRIFT ${name}`);
    console.error(`      vendored copy expects ${entry.sha256}`);
    console.error(`      ${entry.source} is now ${actual}`);
  }
}

if (drifted > 0) {
  console.error(
    `\n${drifted} vendored file(s) out of date. Re-copy them into ` +
      'apps/agent/src/protocol/ and update VENDORED.json.',
  );
  process.exit(1);
}

console.log(checked === 0 ? '\nnothing to check' : `\n${checked} file(s) in sync`);
