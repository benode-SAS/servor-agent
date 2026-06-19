import { mkdirSync, writeFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { BUILD_VERSION } from '../src/version';

// Written after the binaries are compiled so the API advertises ONLY the version
// that was actually built. Bumping the version constant without rebuilding does
// not change this manifest → agents never chase a non-existent binary.
const out = join(import.meta.dir, '..', 'dist', 'manifest.json');
mkdirSync(dirname(out), { recursive: true });
writeFileSync(out, JSON.stringify({ version: BUILD_VERSION, builtAt: new Date().toISOString() }));
process.stdout.write(`manifest written: ${BUILD_VERSION}\n`);
