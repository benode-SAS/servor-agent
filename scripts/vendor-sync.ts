/**
 * Re-copy src/protocol/ from packages/shared and refresh VENDORED.json.
 *
 * ```sh
 * bun run protocol:sync
 * ```
 *
 * @remarks
 * `check-vendored.ts` detects drift; this is the other half — the thing you run
 * once the source has legitimately changed. Doing it by hand means copying the
 * file, re-adding the header, rewriting the imports and recomputing a SHA-256,
 * and forgetting the last step leaves a copy that passes the check while
 * disagreeing with the control plane. That failure is silent and lands on every
 * host in the fleet, which is reason enough for this to be a script.
 *
 * Imports are rewritten to `./<name>` for any specifier whose basename is
 * itself vendored, so the copies resolve against each other and not against a
 * package the standalone repository does not have.
 *
 * @module
 */
import { createHash } from 'node:crypto';
import { readFileSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';

/** One VENDORED.json record: where the file came from, and its hash when copied. */
type Entry = { source: string; sha256: string };

const HEADER = (source: string) =>
  `// Vendored from ${source} — do not edit here.
//
// The agent ships as an independent, auditable artefact: a reader must be
// able to see every line that decides whether a command runs, without
// resolving a private Servor package. \`bun run protocol:check\` fails if this
// copy drifts from the original, because a guard that disagrees with the one
// on the control plane is worse than no guard.

`;

// The leading-slash strip turns a Windows file URL path (/C:/…) back into a path.
// SERVOR_AGENT_DIR retargets the whole sync; nothing sets it in the pipeline.
const here =
  process.env.SERVOR_AGENT_DIR ??
  new URL('..', import.meta.url).pathname.replace(/^\/([A-Za-z]:)/, '$1');
const repoRoot = join(here, '..', '..');
const protocolDir = join(here, 'src', 'protocol');
const manifestPath = join(protocolDir, 'VENDORED.json');

const manifest: Record<string, Entry> = JSON.parse(readFileSync(manifestPath, 'utf-8'));
const vendoredNames = new Set(Object.keys(manifest).map((n) => n.replace(/\.ts$/, '')));

const rewriteImports = (code: string): string =>
  code.replace(/(from\s+')([^']+)(')/g, (whole, open: string, spec: string, close: string) => {
    if (!spec.startsWith('.')) return whole;
    const base = spec.split('/').pop() ?? '';
    return vendoredNames.has(base) ? `${open}./${base}${close}` : whole;
  });

for (const [name, entry] of Object.entries(manifest)) {
  const sourcePath = join(repoRoot, entry.source);
  const source = readFileSync(sourcePath, 'utf-8');
  writeFileSync(join(protocolDir, name), HEADER(entry.source) + rewriteImports(source));
  const sha256 = createHash('sha256').update(source).digest('hex');
  const changed = sha256 !== entry.sha256;
  entry.sha256 = sha256;
  console.log(`${changed ? 'update' : 'ok    '} ${name}`);
}

writeFileSync(manifestPath, `${JSON.stringify(manifest, null, 2)}\n`);
console.log(`\n${Object.keys(manifest).length} file(s) vendored`);
