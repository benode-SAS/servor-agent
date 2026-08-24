/**
 * Verify that src/protocol/ still matches its source in packages/shared.
 *
 * ```sh
 * bun run protocol:check
 * ```
 *
 * @remarks
 * Drift here is not cosmetic. These are the files that decide whether a
 * signature is accepted and whether a command is refused, so a copy that
 * disagrees with the control plane either breaks execution outright or, worse,
 * quietly weakens a guard on one side only. Comparing SHA-256 of the whole file
 * means even a changed comment fails the check — the copies are meant to be
 * identical, and deciding which differences are harmless is exactly the
 * judgement this script exists to avoid.
 *
 * Exits 1 on any drift. In a standalone checkout of the agent the sources are
 * absent, so each entry is skipped and the script succeeds: there is nothing to
 * compare against, which is a different thing from a mismatch.
 *
 * @module
 */
import { createHash } from 'node:crypto';
import { existsSync, readFileSync } from 'node:fs';
import { join } from 'node:path';

/** One VENDORED.json record: where the file came from, and its hash when copied. */
type Entry = { source: string; sha256: string };

// The leading-slash strip turns a Windows file URL path (/C:/…) back into a path.
// SERVOR_AGENT_DIR retargets the whole check; nothing sets it in the pipeline.
const here =
  process.env.SERVOR_AGENT_DIR ??
  new URL('..', import.meta.url).pathname.replace(/^\/([A-Za-z]:)/, '$1');
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
